//! Errors raised by the Linux backend.
//!
//! These cover the Linux monitor-mode control path: the nl80211 generic-netlink
//! socket used to enumerate and reconfigure interfaces, the rtnetlink link
//! toggles, and the D-Bus coordination with whichever network manager is
//! holding the interface (NetworkManager or wpa_supplicant).

use std::io;

use wl_nl80211::Nl80211Error;

/* Types */

/// What an interface reported when its frequency was read back after a set:
/// either a concrete center frequency, or nothing (the interface was not tuned).
///
/// Carried by [`LinuxError::ChannelVerifyFailed`] so the message can distinguish
/// "landed on the wrong frequency" from "reports no frequency at all".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyReadback {
    /// The interface reported this center frequency, in MHz.
    Mhz(u32),
    /// The interface reported no frequency.
    None,
}

impl From<Option<u32>> for FrequencyReadback {
    fn from(value: Option<u32>) -> Self {
        match value {
            Some(mhz) => Self::Mhz(mhz),
            None => Self::None,
        }
    }
}

impl std::fmt::Display for FrequencyReadback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mhz(mhz) => write!(f, "{mhz} MHz"),
            Self::None => f.write_str("none"),
        }
    }
}

/// What an interface reported for its channel *width* when read back after a
/// set.
///
/// The primary frequency alone does not prove a channel set took: a driver can
/// land on the right frequency at the wrong bandwidth, which quietly halves what
/// a wide capture sees. Carried by [`LinuxError::WidthVerifyFailed`].
///
/// A 40 MHz channel is only fully described by its segment centre, which is what
/// distinguishes HT40+ from HT40-, hence the separate
/// [`Misaligned`](Self::Misaligned) case for a device reporting 40 MHz whose
/// centre sits neither 10 MHz above nor 10 MHz below the primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidthReadback {
    /// The interface reported a width this library can request.
    Known(crate::interface::ChannelWidth),
    /// The interface reported 40 MHz, but the segment centre is neither
    /// primary + 10 nor primary - 10 MHz.
    Misaligned {
        /// The segment centre the interface reported, if it reported one.
        center_mhz: Option<u32>,
    },
    /// The interface reported a width this library never requests (80, 160, …).
    Other {
        /// The reported width, in MHz.
        mhz: u32,
    },
    /// The interface reported no channel width at all.
    None,
}

impl std::fmt::Display for WidthReadback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Known(width) => write!(f, "{width}"),
            Self::Misaligned {
                center_mhz: Some(mhz),
            } => write!(f, "40 MHz with segment centre {mhz} MHz"),
            Self::Misaligned { center_mhz: None } => {
                f.write_str("40 MHz with no segment centre reported")
            }
            Self::Other { mhz } => write!(f, "{mhz} MHz"),
            Self::None => f.write_str("none"),
        }
    }
}

/// A failure originating in the Linux backend.
///
/// `#[non_exhaustive]` for the same reason as [`Error`](crate::Error): the set
/// of ways the nl80211/D-Bus control path can fail is not closed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinuxError {
    /* Netlink transport */
    //
    // Failures talking to the kernel over generic netlink / rtnetlink.
    /// A netlink socket could not be opened.
    #[error("failed to open {kind} netlink socket during {phase}: {source}")]
    NetlinkConnect {
        /// Which socket failed to open, e.g. `"nl80211"` or `"rtnetlink"`.
        kind: &'static str,
        /// Phase at which the socket setup failed, e.g. `"connect"`.
        phase: &'static str,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// A netlink dump (`get_interface` / `get_wiphy`) returned an error.
    #[error("nl80211 {command} dump failed: {source}")]
    Dump {
        /// The nl80211 command being dumped, e.g. `"get_interface"`.
        command: &'static str,
        /// Underlying nl80211 protocol error.
        #[source]
        source: Nl80211Error,
    },

    /// A netlink dump did not complete within its deadline.
    #[error("nl80211 {command} dump timed out after {timeout_ms} ms")]
    Timeout {
        /// The nl80211 command being dumped, e.g. `"get_wiphy"`.
        command: &'static str,
        /// Deadline that elapsed, in milliseconds.
        timeout_ms: u64,
    },

    /// A control operation (mode switch, rename, channel set, or a D-Bus
    /// coordination call) did not complete within its deadline.
    ///
    /// Unlike the dump [`Timeout`](Self::Timeout), this bounds the mutating
    /// paths (including the D-Bus calls reached from teardown), so a wedged
    /// system bus or driver cannot hang a caller (or a blocking `Drop`)
    /// indefinitely.
    #[error("{op} timed out after {timeout_ms} ms")]
    OperationTimeout {
        /// Human-readable operation that timed out, e.g. `"NetworkManager release"`.
        op: &'static str,
        /// Deadline that elapsed, in milliseconds.
        timeout_ms: u64,
    },

    /* Mode switching */
    //
    // Failures reconfiguring an interface between operating modes.
    /// Bringing the interface link up or down (rtnetlink) failed.
    #[error("failed to bring interface '{iface}' link {op}: {source}")]
    LinkSet {
        /// `"up"` or `"down"`.
        op: &'static str,
        /// The interface the operation targeted.
        iface: String,
        /// Underlying rtnetlink error.
        #[source]
        source: rtnetlink::Error,
    },

    /// The nl80211 `SET_INTERFACE` type change failed.
    #[error("failed to set interface '{iface}' mode via nl80211: {source}")]
    SetMode {
        /// The interface the operation targeted.
        iface: String,
        /// Underlying nl80211 error.
        #[source]
        source: Nl80211Error,
    },

    /// The nl80211 channel/frequency set (`SET_WIPHY`) failed.
    #[error("failed to set interface '{iface}' channel via nl80211: {source}")]
    SetChannel {
        /// The interface the operation targeted.
        iface: String,
        /// Underlying nl80211 error.
        #[source]
        source: Nl80211Error,
    },

    /// The interface did not report the requested *frequency* after the set.
    ///
    /// `SET_WIPHY` was accepted but reading the frequency back showed a
    /// different value, or none. The same empirical confirmation
    /// [`MonitorVerifyFailed`](Self::MonitorVerifyFailed) gives for mode
    /// switches, since drivers can accept a channel set without honoring it.
    ///
    /// The bandwidth is checked separately; see
    /// [`WidthVerifyFailed`](Self::WidthVerifyFailed).
    #[error(
        "interface '{iface}' did not tune to {requested_mhz} MHz after the set \
         (reads as {actual})"
    )]
    ChannelVerifyFailed {
        /// The interface that failed to confirm the frequency.
        iface: String,
        /// The center frequency that was requested, in MHz.
        requested_mhz: u32,
        /// What the interface reported instead: another frequency, or `none`.
        actual: FrequencyReadback,
    },

    /// The interface tuned to the right frequency at the wrong bandwidth.
    ///
    /// Verified separately from [`ChannelVerifyFailed`](Self::ChannelVerifyFailed)
    /// because it is a different failure with a different consequence: the
    /// capture is on the intended channel but only sees part of it, which is far
    /// easier to miss than landing on the wrong frequency outright. Drivers
    /// commonly accept a 40 MHz request and fall back to 20.
    #[error(
        "interface '{iface}' tuned to {primary_mhz} MHz but at {actual} rather than \
         the requested {requested}"
    )]
    WidthVerifyFailed {
        /// The interface that failed to confirm the width.
        iface: String,
        /// The primary frequency that *was* confirmed, in MHz.
        primary_mhz: u32,
        /// The width that was requested.
        requested: crate::interface::ChannelWidth,
        /// What the interface reported instead.
        actual: WidthReadback,
    },

    /// The interface did not report monitor mode after the switch was applied.
    ///
    /// The mode change was accepted but the driver did not actually enter
    /// monitor mode: the empirical confirmation that a device without an
    /// advertised monitor iftype can still capture.
    #[error("interface '{iface}' did not enter monitor mode after the switch")]
    MonitorVerifyFailed {
        /// The interface that failed to confirm monitor mode.
        iface: String,
    },

    /// The interface did not report managed mode after being restored.
    ///
    /// The mirror of [`MonitorVerifyFailed`](Self::MonitorVerifyFailed) on the
    /// way out. A driver that accepts the switch back without honoring it leaves
    /// the radio capturing while every caller believes it was released, and a
    /// recovery sweep would report it as restored. Carries what the interface
    /// reported instead, since "still in monitor" and "ended up somewhere else
    /// entirely" are different problems.
    #[error(
        "interface '{iface}' did not return to managed mode after the switch (reads as {actual})"
    )]
    ManagedVerifyFailed {
        /// The interface that failed to confirm managed mode.
        iface: String,
        /// The mode the interface reported instead.
        actual: crate::interface::InterfaceMode,
    },

    /// Renaming the interface (rtnetlink) failed.
    #[error("failed to rename interface '{old}' to '{new}': {source}")]
    Rename {
        /// The name before the rename.
        old: String,
        /// The requested new name.
        new: String,
        /// Underlying rtnetlink error.
        #[source]
        source: rtnetlink::Error,
    },

    /* Network-manager coordination (D-Bus) */
    //
    // Failures releasing/reclaiming the interface from whatever service holds
    // it. All of these are best-effort: a missing service is not an error (the
    // interface is simply not managed), only a present service that refuses.
    // Present only with the `dbus` feature, which carries the coordination.
    /// The system D-Bus connection could not be established.
    #[cfg(feature = "dbus")]
    #[error("failed to connect to the system D-Bus: {source}")]
    DbusConnect {
        /// Underlying D-Bus error.
        #[source]
        source: zbus::Error,
    },

    /// A NetworkManager D-Bus operation failed for a specific interface.
    #[cfg(feature = "dbus")]
    #[error("NetworkManager {op} failed for interface '{iface}': {source}")]
    NetworkManager {
        /// The operation being attempted, e.g. `"get_device"` or `"set_unmanaged"`.
        op: &'static str,
        /// The interface the operation targeted.
        iface: String,
        /// Underlying D-Bus error.
        #[source]
        source: zbus::Error,
    },

    /// A wpa_supplicant D-Bus operation failed for a specific interface.
    #[cfg(feature = "dbus")]
    #[error("wpa_supplicant {op} failed for interface '{iface}': {source}")]
    Supplicant {
        /// The operation being attempted, e.g. `"remove_interface"`.
        op: &'static str,
        /// The interface the operation targeted.
        iface: String,
        /// Underlying D-Bus error.
        #[source]
        source: zbus::Error,
    },
}
