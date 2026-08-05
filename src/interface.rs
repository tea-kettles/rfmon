//! Wireless-interface data model and capture-selection policy.
//!
//! This module holds the *platform-neutral* view of a wireless interface: its
//! identity, operating mode, and the capabilities of its physical device, plus
//! the pure scoring logic that ranks interfaces as monitor-mode candidates.
//!
//! The values here are produced by a platform backend (on Linux, by joining the
//! nl80211 interface and wiphy dumps; see [`crate::linux::interface`]). Nothing
//! in this file talks to the kernel, which keeps the selection policy
//! unit-testable without touching hardware.

use crate::{MacAddr, Result};

/* Constants */

// Capture-selection score weights (see `WirelessInterface::monitor_score`).
// The associated penalty dominates: an interface carrying the host's live
// connection is avoided unless nothing else can do the job.
const SCORE_KNOWN_MONITOR_DRIVER: i32 = 40;
const SCORE_USB_BUS: i32 = 30;
const SCORE_ADVERTISES_MONITOR: i32 = 20;
const SCORE_OTHER_BUS: i32 = 5;
const SCORE_DUAL_BAND: i32 = 2;
const SCORE_ASSOCIATED_PENALTY: i32 = -100;

// Longest name the kernel accepts for a netdev. `IFNAMSIZ` is 16 bytes
// including the trailing NUL, leaving 15 usable characters. See
// `validate_iface_name`.
const MAX_IFACE_NAME_LEN: usize = 15;

// Driver-name fragments for families known to support monitor mode (and, in
// practice, frame injection) regardless of what they advertise over nl80211.
// This is a heuristic prior; monitor capability is confirmed empirically later
// by actually entering monitor mode and reading the mode back.
//
// Matching is by substring (see `is_known_monitor_driver`), so every token must
// be *minimal*: a token that contains another token in the list is dead weight,
// since any driver matching the longer one already matches the shorter. The
// `driver_tokens_are_minimal` test enforces this. For example, `mt76` already covers
// `mt76x2u`, and `8812au` already covers `rtl8812au`, so those longer forms are
// deliberately absent. `mt7921u` stays: `mt76` is not a substring of it.
const MONITOR_DRIVER_TOKENS: &[&str] = &[
    "ath9k",
    "carl9170",
    "rtl8187",
    "rtl8821",
    "8812au",
    "88xxau",
    "8814au",
    "8821au",
    "rt2800usb",
    "rt2800pci",
    "rt73usb",
    "rt2500usb",
    "mt7921u",
    "mt76",
];

/* Types */

/// 802.11 interface operating mode.
///
/// A subset of nl80211's `iftype`s that this library reasons about; anything
/// else is preserved as [`InterfaceMode::Other`] with its raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceMode {
    /// Managed / station mode (a normal client).
    Managed,
    /// Monitor mode. Receives raw 802.11 frames; the mode this library targets.
    Monitor,
    /// Access-point mode.
    Ap,
    /// Ad-hoc / IBSS mode.
    Adhoc,
    /// Mesh point.
    MeshPoint,
    /// Any other nl80211 iftype, by raw value.
    Other(u32),
}

/// A frequency band a physical device supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BandKind {
    /// 2.4 GHz (802.11b/g/n/ax).
    TwoGhz,
    /// 5 GHz (802.11a/n/ac/ax).
    FiveGhz,
    /// 6 GHz (802.11ax/be).
    SixGhz,
    /// 60 GHz (802.11ad/ay).
    SixtyGhz,
    /// Any other nl80211 band, by raw value.
    Other(u16),
}

/// The physical bus a wireless device sits on.
///
/// Used as a selection signal: an external USB adapter (an Alfa-class device)
/// is almost always the radio the operator deliberately attached for capture,
/// whereas the built-in PCIe card is usually the host's own connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusKind {
    /// USB. Typically a removable, purpose-attached adapter.
    Usb,
    /// PCI/PCIe. Typically the built-in card.
    Pci,
    /// Anything else, or undetermined.
    Other,
}

/// Channel bandwidth for [`set_channel`](crate::set_channel).
///
/// [`Mhz20`](Self::Mhz20) is the default and carries all management and EAPOL
/// traffic regardless of the AP's operating width, so it is all you need to
/// observe a handshake. The 40 MHz variants exist for capturing wide,
/// high-throughput data; they place the secondary channel above or below the
/// primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelWidth {
    /// 20 MHz (no-HT). The default; always safe and enough for EAPOL.
    #[default]
    Mhz20,
    /// 40 MHz with the secondary channel above the primary (HT40+).
    Mhz40Above,
    /// 40 MHz with the secondary channel below the primary (HT40-).
    Mhz40Below,
}

/// A single channel/frequency the device can operate on.
///
/// Monitor mode is receive-only, so this carries just what a capture setup
/// needs: the frequency, its channel number, and whether the regulatory domain
/// disables or radar-flags it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frequency {
    pub(crate) mhz: u32,
    pub(crate) channel: Option<u32>,
    pub(crate) disabled: bool,
    pub(crate) radar: bool,
}

/// Which bands a channel number is resolved against.
///
/// 6 GHz reuses channel numbers that 2.4 GHz and 5 GHz already use: 1, 5, 9 and
/// 13 collide with 2.4 GHz, and 149 through 177 collide with 5 GHz UNII-3, so a
/// bare channel number only identifies one frequency once 6 GHz is either
/// included or excluded. Rather than make that a flag the caller can forget,
/// each `set_channel*` entry point pins its own scope:
/// [`set_channel`](crate::set_channel) is [`ExceptSixGhz`](Self::ExceptSixGhz)
/// and [`set_channel_6g`](crate::set_channel_6g) is
/// [`SixGhzOnly`](Self::SixGhzOnly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BandScope {
    /// Every band except 6 GHz. Channel numbers do not collide across these.
    ExceptSixGhz,
    /// 6 GHz only.
    SixGhzOnly,
}

/// A supported band together with its usable frequencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Band {
    pub(crate) kind: BandKind,
    pub(crate) frequencies: Vec<Frequency>,
}

/// A wireless interface joined with the capabilities of its physical device.
///
/// Obtain instances via [`WirelessInterface::detect`]. Fields are populated by
/// the active platform backend.
#[derive(Debug, Clone)]
pub struct WirelessInterface {
    pub(crate) name: String,
    pub(crate) index: u32,
    pub(crate) phy_index: u32,
    pub(crate) mac: MacAddr,
    pub(crate) mode: InterfaceMode,
    pub(crate) supported_modes: Vec<InterfaceMode>,
    pub(crate) bands: Vec<Band>,
    // Kernel driver bound to the physical device, e.g. `rtl8812au`; `None` if it
    // could not be determined.
    pub(crate) driver: Option<String>,
    // Physical bus (USB/PCI) the device sits on.
    pub(crate) bus: BusKind,
    // SSID this interface is currently associated to, if any. Its presence is
    // how we know the interface is carrying a live connection.
    pub(crate) ssid: Option<String>,
}

/* Implementations */

impl std::fmt::Display for InterfaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Managed => f.write_str("managed"),
            Self::Monitor => f.write_str("monitor"),
            Self::Ap => f.write_str("AP"),
            Self::Adhoc => f.write_str("adhoc"),
            Self::MeshPoint => f.write_str("mesh"),
            Self::Other(v) => write!(f, "iftype({v})"),
        }
    }
}

impl std::fmt::Display for BandKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TwoGhz => f.write_str("2.4 GHz"),
            Self::FiveGhz => f.write_str("5 GHz"),
            Self::SixGhz => f.write_str("6 GHz"),
            Self::SixtyGhz => f.write_str("60 GHz"),
            Self::Other(v) => write!(f, "band({v})"),
        }
    }
}

impl std::fmt::Display for ChannelWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mhz20 => f.write_str("20 MHz"),
            Self::Mhz40Above => f.write_str("40 MHz (HT40+)"),
            Self::Mhz40Below => f.write_str("40 MHz (HT40-)"),
        }
    }
}

impl std::fmt::Display for BusKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usb => f.write_str("usb"),
            Self::Pci => f.write_str("pci"),
            Self::Other => f.write_str("other"),
        }
    }
}

impl BandScope {
    // Whether a band is searched under this scope.
    fn includes(self, kind: BandKind) -> bool {
        match self {
            Self::ExceptSixGhz => kind != BandKind::SixGhz,
            Self::SixGhzOnly => kind == BandKind::SixGhz,
        }
    }

    // The entry point that searches the bands this scope leaves out, named for
    // the error that suggests it.
    fn alternative(self) -> &'static str {
        match self {
            Self::ExceptSixGhz => "set_channel_6g",
            Self::SixGhzOnly => "set_channel",
        }
    }
}

impl Frequency {
    /// The center frequency in MHz.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// for iface in WirelessInterface::detect().await? {
    ///     for freq in iface.frequencies() {
    ///         println!("{} MHz", freq.mhz());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn mhz(&self) -> u32 {
        self.mhz
    }

    /// The IEEE channel number, if it maps to a known one.
    ///
    /// `None` for a frequency off the recognized channel grid; pass it to
    /// [`set_channel`](crate::set_channel) by number only when this is `Some`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// let tunable: Vec<u32> = iface.frequencies().filter_map(|f| f.channel()).collect();
    /// println!("{} channels addressable by number", tunable.len());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn channel(&self) -> Option<u32> {
        self.channel
    }

    /// Whether the channel is disabled in the current regulatory domain.
    ///
    /// A disabled channel cannot be tuned;
    /// [`set_channel`](crate::set_channel) skips these when resolving, so
    /// asking for one yields `ChannelUnavailable`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// let usable = iface.frequencies().filter(|f| !f.is_disabled()).count();
    /// println!("{usable} usable frequencies in this regulatory domain");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Whether the channel is radar/DFS.
    ///
    /// Monitor mode is receive-only, so a DFS channel is safe to sit on, so this
    /// is informational rather than a restriction.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// for freq in iface.frequencies().filter(|f| f.is_radar()) {
    ///     println!("{} MHz is a DFS channel", freq.mhz());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn is_radar(&self) -> bool {
        self.radar
    }
}

impl Band {
    /// The band this frequency set belongs to.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::{BandKind, WirelessInterface};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// let six_e = iface.bands().iter().any(|b| b.kind() == BandKind::SixGhz);
    /// println!("6 GHz capable: {six_e}");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn kind(&self) -> BandKind {
        self.kind
    }

    /// The frequencies the device supports in this band.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// for band in iface.bands() {
    ///     println!("{}: {} frequencies", band.kind(), band.frequencies().len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn frequencies(&self) -> &[Frequency] {
        &self.frequencies
    }
}

impl WirelessInterface {
    /// Kernel interface name, e.g. `wlan0`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// for iface in WirelessInterface::detect().await? {
    ///     println!("{}", iface.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// nl80211 interface index (`if_index`).
    ///
    /// Stable across a rename, which is why teardown addresses the interface by
    /// index rather than by name.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// println!("{} is if_index {}", iface.name(), iface.index());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Index of the physical device (wiphy) backing this interface.
    ///
    /// Several interfaces can share one wiphy, in which case they share its
    /// capabilities: bands, channels, and supported modes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// for iface in WirelessInterface::detect().await? {
    ///     println!("{} sits on phy{}", iface.name(), iface.phy_index());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn phy_index(&self) -> u32 {
        self.phy_index
    }

    /// Hardware MAC address of the interface.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// println!("{} has MAC {}", iface.name(), iface.mac());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// The interface's current operating mode.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::{InterfaceMode, WirelessInterface};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// if iface.mode() == InterfaceMode::Managed {
    ///     println!("{} is a normal client right now", iface.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn mode(&self) -> InterfaceMode {
        self.mode
    }

    /// Operating modes the physical device supports.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// let modes: Vec<String> = iface.supported_modes().iter().map(|m| m.to_string()).collect();
    /// println!("{} supports: {}", iface.name(), modes.join(", "));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn supported_modes(&self) -> &[InterfaceMode] {
        &self.supported_modes
    }

    /// Supported frequency bands and their channels.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// for band in iface.bands() {
    ///     println!("{}", band.kind());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn bands(&self) -> &[Band] {
        &self.bands
    }

    /// Every supported frequency across all bands.
    ///
    /// The flattened view of [`bands`](Self::bands), for when the band a
    /// frequency belongs to does not matter.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// println!("{} frequencies in total", iface.frequencies().count());
    /// # Ok(())
    /// # }
    /// ```
    // No `#[must_use]`: `Iterator` already carries one, and adding a second is
    // redundant (clippy::double_must_use).
    pub fn frequencies(&self) -> impl Iterator<Item = &Frequency> {
        self.bands.iter().flat_map(|band| band.frequencies.iter())
    }

    /// Whether the physical device advertises monitor mode over nl80211.
    ///
    /// Note this is only what the device *advertises*; some monitor-capable
    /// adapters (notably Realtek USB) do not, which is why selection also
    /// consults [`is_monitor_plausible`](Self::is_monitor_plausible).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// if !iface.supports_monitor() && iface.is_monitor_plausible() {
    ///     println!("{} does not advertise monitor mode but probably has it", iface.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn supports_monitor(&self) -> bool {
        self.supported_modes.contains(&InterfaceMode::Monitor)
    }

    /// Whether the interface is currently in monitor mode.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// // What `stop_all_monitors` sweeps.
    /// for iface in WirelessInterface::detect().await?.iter().filter(|i| i.is_monitor()) {
    ///     println!("{} is still in monitor mode", iface.name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn is_monitor(&self) -> bool {
        self.mode == InterfaceMode::Monitor
    }

    /// Kernel driver bound to the physical device (e.g. `rtl8812au`), if known.
    ///
    /// `None` when the sysfs link could not be read; treat it as an unknown
    /// driver rather than an error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// println!("{} uses {}", iface.name(), iface.driver().unwrap_or("an unknown driver"));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn driver(&self) -> Option<&str> {
        self.driver.as_deref()
    }

    /// The physical bus (USB/PCI) this device sits on.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::{BusKind, WirelessInterface};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// // External adapters are the ones deliberately attached for capture.
    /// for iface in WirelessInterface::detect().await? {
    ///     if iface.bus() == BusKind::Usb {
    ///         println!("{} is external", iface.name());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn bus(&self) -> BusKind {
        self.bus
    }

    /// The SSID this interface is currently associated to, if any.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// # let iface = WirelessInterface::detect().await?.remove(0);
    /// match iface.ssid() {
    ///     Some(ssid) => println!("{} is on {ssid}", iface.name()),
    ///     None => println!("{} is idle", iface.name()),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn ssid(&self) -> Option<&str> {
        self.ssid.as_deref()
    }

    /// Whether the interface currently carries a live association.
    ///
    /// Commandeering an associated interface for monitor mode drops that
    /// connection, so selection penalizes it heavily.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// // Pick a radio that is not carrying the host's uplink.
    /// let interfaces = WirelessInterface::detect().await?;
    /// let idle = interfaces.iter().find(|i| !i.is_associated());
    /// println!("{:?}", idle.map(|i| i.name()));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn is_associated(&self) -> bool {
        self.ssid.is_some()
    }

    /// Whether monitor mode is *plausible* for this interface.
    ///
    /// True if the physical device either advertises monitor mode or is bound
    /// to a driver family known to support monitor mode in practice. The latter
    /// matters because vendor USB drivers (notably Realtek's `rtl88xxau`)
    /// support monitor via a type switch without advertising it through
    /// nl80211, so [`supports_monitor`](Self::supports_monitor) alone would
    /// wrongly reject exactly the adapters bought for capture. Ground-truth
    /// confirmation happens later by actually entering monitor mode.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// // The filter `start_monitor` applies before scoring the survivors.
    /// let interfaces = WirelessInterface::detect().await?;
    /// let candidates = interfaces.iter().filter(|i| i.is_monitor_plausible()).count();
    /// println!("{candidates} plausible capture radio(s)");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn is_monitor_plausible(&self) -> bool {
        self.supports_monitor() || self.driver.as_deref().is_some_and(is_known_monitor_driver)
    }

    /// A heuristic score ranking this interface as a monitor-capture candidate.
    ///
    /// Higher is better. The model combines capability signals (known
    /// monitor-capable driver, advertised monitor) with a preference for
    /// external USB adapters and a heavy penalty for interfaces that currently
    /// carry a live connection, since selecting one of those would drop the host's
    /// link.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mut interfaces = WirelessInterface::detect().await?;
    /// // The same ranking `start_monitor` applies internally.
    /// interfaces.sort_by_key(|iface| -iface.monitor_score());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn monitor_score(&self) -> i32 {
        let mut score = 0;

        if self.driver.as_deref().is_some_and(is_known_monitor_driver) {
            score += SCORE_KNOWN_MONITOR_DRIVER;
        }
        score += match self.bus {
            BusKind::Usb => SCORE_USB_BUS,
            BusKind::Other => SCORE_OTHER_BUS,
            BusKind::Pci => 0,
        };
        if self.supports_monitor() {
            score += SCORE_ADVERTISES_MONITOR;
        }
        if self.is_associated() {
            score += SCORE_ASSOCIATED_PENALTY;
        }
        if self.bands.iter().any(|b| b.kind == BandKind::FiveGhz) {
            score += SCORE_DUAL_BAND;
        }

        score
    }

    /// Detect every wireless interface on the system, each joined with the
    /// capabilities of its physical device.
    ///
    /// Dispatches to the active platform backend.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::WirelessInterface;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// for iface in WirelessInterface::detect().await? {
    ///     println!("{} (score {})", iface.name(), iface.monitor_score());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn detect() -> Result<Vec<WirelessInterface>> {
        crate::monitor::detect().await
    }
}

/* Free functions */

/// Map a center frequency in MHz to its IEEE channel number, if known.
///
/// Covers 2.4 GHz, 5 GHz, and 6 GHz (including the special 6 GHz channel 2 at
/// 5935 MHz). Returns `None` for frequencies that do not sit on a recognized
/// channel grid.
///
/// # Examples
///
/// ```
/// use rfmon::channel_from_mhz;
///
/// assert_eq!(channel_from_mhz(2412), Some(1));   // 2.4 GHz ch 1
/// assert_eq!(channel_from_mhz(2437), Some(6));   // 2.4 GHz ch 6
/// assert_eq!(channel_from_mhz(2484), Some(14));  // 2.4 GHz ch 14
/// assert_eq!(channel_from_mhz(5180), Some(36));  // 5 GHz ch 36
/// assert_eq!(channel_from_mhz(5955), Some(1));   // 6 GHz ch 1
/// assert_eq!(channel_from_mhz(3000), None);
/// assert_eq!(channel_from_mhz(2413), None);      // between channels 1 and 2
/// ```
#[must_use]
pub fn channel_from_mhz(mhz: u32) -> Option<u32> {
    // The frequencies below are written inline rather than lifted into named
    // constants: they are the IEEE grid definition itself, and a name like
    // `BAND_2GHZ_BASE_MHZ` restates `2407` without adding meaning. The
    // structure they encode is what needs explaining, so it is explained here.
    //
    // Each band's channels sit on a 5 MHz grid anchored at a base frequency.
    // Require exact grid alignment so a frequency *between* channels resolves to
    // `None` rather than silently truncating onto the nearest channel below it
    // (e.g. 2413 -> 1). The lower bounds also exclude channel 0, which the
    // linear formula would otherwise produce at the base frequency itself.
    match mhz {
        2412..=2472 if (mhz - 2412) % 5 == 0 => Some((mhz - 2407) / 5),
        2484 => Some(14),
        // 6 GHz channel 2 is the outlier below the linear grid.
        5935 => Some(2),
        5005..=5895 if (mhz - 5000) % 5 == 0 => Some((mhz - 5000) / 5),
        5955..=7115 if (mhz - 5950) % 5 == 0 => Some((mhz - 5950) / 5),
        _ => None,
    }
}

// Whether a driver name belongs to a family known to support monitor mode.
pub(crate) fn is_known_monitor_driver(driver: &str) -> bool {
    let driver = driver.to_ascii_lowercase();
    MONITOR_DRIVER_TOKENS
        .iter()
        .any(|token| driver.contains(token))
}

// Order two candidates: highest score wins, ties break toward the lower
// interface index so selection is deterministic across runs.
fn rank(a: &WirelessInterface, b: &WirelessInterface) -> std::cmp::Ordering {
    a.monitor_score()
        .cmp(&b.monitor_score())
        .then_with(|| b.index.cmp(&a.index))
}

// Every usable candidate, best first. Pure over its input so the selection
// policy is unit-testable without touching hardware.
//
// The whole ordered list rather than just the winner, because monitor capability
// cannot be known until it is tried: the driver-name heuristic is a prior, and a
// radio that advertises monitor mode can still refuse the switch. The caller
// works down the list until one is confirmed.
pub(crate) fn rank_candidates(
    interfaces: Vec<WirelessInterface>,
) -> Result<Vec<WirelessInterface>> {
    if interfaces.is_empty() {
        return Err(crate::Error::NoInterfaces);
    }
    let checked = interfaces.len();

    let plausible: Vec<WirelessInterface> = interfaces
        .into_iter()
        .filter(WirelessInterface::is_monitor_plausible)
        .collect();
    if plausible.is_empty() {
        return Err(crate::Error::NoMonitorCapable { checked });
    }

    // A radio already in monitor mode is out of the running: something else put
    // it there, and commandeering it is destructive in both directions (see
    // `Error::AlreadyMonitor`). Partitioned rather than filtered so the error
    // can name the radio that *would* have been chosen.
    let (mut idle, busy): (Vec<WirelessInterface>, Vec<WirelessInterface>) =
        plausible.into_iter().partition(|iface| !iface.is_monitor());

    if idle.is_empty() {
        let blocked = busy
            .into_iter()
            .max_by(rank)
            .expect("busy is non-empty: plausible was non-empty and idle is empty");
        return Err(crate::Error::AlreadyMonitor {
            iface: blocked.name,
        });
    }

    // `rank` orders worst-to-best, so compare reversed to get best-first.
    idle.sort_by(|a, b| rank(b, a));
    Ok(idle)
}

// The single best candidate. Test-only: production works down the whole ranked
// list, but the selection tests are about who wins, and threading `[0]` through
// every one of them would obscure that.
#[cfg(test)]
pub(crate) fn pick_best(interfaces: Vec<WirelessInterface>) -> Result<WirelessInterface> {
    rank_candidates(interfaces).map(|mut ranked| ranked.remove(0))
}

// Resolve a channel number to the device's actual center frequency in MHz,
// searching only the bands this device supports and only those the scope
// admits. Pure over its input, so it is unit-testable.
//
// A miss that would have hit under the *other* scope reports `WrongBand` rather
// than `ChannelUnavailable`, so a 6 GHz number typed into `set_channel` says so
// instead of claiming the device cannot reach it.
pub(crate) fn resolve_frequency(
    iface: &WirelessInterface,
    channel: u32,
    scope: BandScope,
) -> Result<u32> {
    let mut freqs: Vec<u32> = Vec::new();
    // Set when the channel exists on this device but in a band the scope skips.
    let mut out_of_scope = false;
    // Set when the channel is in scope and present, but the regulatory domain
    // rules it out: a different problem with a different fix.
    let mut disabled = false;

    for band in iface.bands() {
        for freq in band.frequencies() {
            if freq.channel() != Some(channel) {
                continue;
            }
            if !scope.includes(band.kind()) {
                // Only a channel that is actually usable in the other band is
                // worth redirecting the caller to.
                out_of_scope |= !freq.is_disabled();
                continue;
            }
            if freq.is_disabled() {
                disabled = true;
                continue;
            }
            freqs.push(freq.mhz());
        }
    }
    freqs.sort_unstable();
    freqs.dedup();

    match freqs.as_slice() {
        // Ordered by how actionable each answer is. A reachable channel in the
        // other band beats everything: there is a call that works right now.
        [] if out_of_scope => Err(crate::Error::WrongBand {
            channel,
            iface: iface.name().to_string(),
            alternative: scope.alternative(),
        }),
        // Then the regulatory domain, which is a setting the operator can
        // change, unlike hardware that simply cannot reach the frequency.
        [] if disabled => Err(crate::Error::ChannelDisabled {
            channel,
            iface: iface.name().to_string(),
        }),
        [] => Err(crate::Error::ChannelUnavailable {
            channel,
            iface: iface.name().to_string(),
        }),
        [one] => Ok(*one),
        _ => Err(crate::Error::AmbiguousChannel {
            channel,
            iface: iface.name().to_string(),
        }),
    }
}

// Validate a candidate interface name against the kernel's constraints for a
// netdev name. These mirror the kernel's own `dev_valid_name`: `IFNAMSIZ` is 16
// including the NUL (so 15 usable characters); no whitespace, `/`, or `:`; and
// the names `.` and `..` are rejected outright because they alias directory
// entries in sysfs (`/sys/class/net/<name>`), which the kernel refuses.
//
// `:` is rejected for the same reason the kernel rejects it: it is the
// separator for alias interfaces (`eth0:1`), so a name containing one is
// ambiguous. Catching it here turns a name like `mon:0` into an
// `InvalidInterfaceName` before the rename is attempted, rather than an
// rtnetlink failure partway through `start_monitor_as`.
pub(crate) fn validate_iface_name(name: &str) -> Result<()> {
    let reason = if name.is_empty() {
        Some("must not be empty")
    } else if name.len() > MAX_IFACE_NAME_LEN {
        Some("must be at most 15 characters")
    } else if name == "." || name == ".." {
        Some("must not be '.' or '..'")
    } else if name.contains('/') || name.contains(':') || name.chars().any(char::is_whitespace) {
        Some("must not contain whitespace, '/', or ':'")
    } else {
        None
    };

    match reason {
        Some(reason) => Err(crate::Error::InvalidInterfaceName {
            name: name.to_string(),
            reason,
        }),
        None => Ok(()),
    }
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_mapping_covers_anchors() {
        // 2.4 GHz
        assert_eq!(channel_from_mhz(2412), Some(1));
        assert_eq!(channel_from_mhz(2462), Some(11));
        assert_eq!(channel_from_mhz(2484), Some(14));
        // 5 GHz
        assert_eq!(channel_from_mhz(5180), Some(36));
        assert_eq!(channel_from_mhz(5745), Some(149));
        // 6 GHz
        assert_eq!(channel_from_mhz(5935), Some(2));
        assert_eq!(channel_from_mhz(5955), Some(1));
        assert_eq!(channel_from_mhz(6175), Some(45));
    }

    #[test]
    fn channel_mapping_rejects_off_grid() {
        assert_eq!(channel_from_mhz(0), None);
        assert_eq!(channel_from_mhz(3000), None);
        assert_eq!(channel_from_mhz(5900), None);
        // Between grid points: must not truncate onto the channel below.
        assert_eq!(channel_from_mhz(2413), None); // between 2.4 GHz ch 1 and 2
        assert_eq!(channel_from_mhz(5182), None); // between 5 GHz ch 36 and 37
        assert_eq!(channel_from_mhz(5957), None); // between 6 GHz ch 1 and 5
        // Base frequencies would yield the non-existent channel 0.
        assert_eq!(channel_from_mhz(5000), None);
        assert_eq!(channel_from_mhz(5950), None);
    }

    #[test]
    fn driver_tokens_are_minimal() {
        // Matching is by substring, so any token that contains another is dead
        // weight: the shorter one already matches everything the longer does.
        // This guards against a well-meaning future PR re-adding, say,
        // `rtl8812au` next to `8812au`.
        for (i, longer) in MONITOR_DRIVER_TOKENS.iter().enumerate() {
            for (j, shorter) in MONITOR_DRIVER_TOKENS.iter().enumerate() {
                if i != j {
                    assert!(
                        !longer.contains(shorter),
                        "token `{longer}` is subsumed by `{shorter}` and can never match \
                         independently; remove it",
                    );
                }
            }
        }
    }

    #[test]
    fn interface_mode_display_is_stable() {
        assert_eq!(InterfaceMode::Managed.to_string(), "managed");
        assert_eq!(InterfaceMode::Monitor.to_string(), "monitor");
        assert_eq!(InterfaceMode::Other(9).to_string(), "iftype(9)");
    }

    #[test]
    fn band_kind_displays() {
        assert_eq!(BandKind::TwoGhz.to_string(), "2.4 GHz");
        assert_eq!(BandKind::SixtyGhz.to_string(), "60 GHz");
    }

    // Build a bare interface for selection/scoring tests.
    fn test_iface(
        name: &str,
        index: u32,
        supported_modes: Vec<InterfaceMode>,
        driver: Option<&str>,
        bus: BusKind,
        ssid: Option<&str>,
    ) -> WirelessInterface {
        WirelessInterface {
            name: name.to_string(),
            index,
            phy_index: 0,
            mac: MacAddr::ZERO,
            mode: InterfaceMode::Managed,
            supported_modes,
            bands: Vec::new(),
            driver: driver.map(str::to_string),
            bus,
            ssid: ssid.map(str::to_string),
        }
    }

    #[test]
    fn driver_match_is_case_insensitive() {
        assert!(is_known_monitor_driver("rtl8812au"));
        assert!(is_known_monitor_driver("RTL88XXAU"));
        assert!(is_known_monitor_driver("ath9k_htc"));
        assert!(!is_known_monitor_driver("rtw89_8852be"));
        assert!(!is_known_monitor_driver("iwlwifi"));
    }

    #[test]
    fn alfa_is_plausible_unadvertised() {
        // The Alfa case: driver supports monitor in practice, advertises none.
        let alfa = test_iface(
            "wlan0",
            2,
            vec![InterfaceMode::Managed, InterfaceMode::Ap],
            Some("rtl8812au"),
            BusKind::Usb,
            None,
        );
        assert!(!alfa.supports_monitor());
        assert!(alfa.is_monitor_plausible());
    }

    #[test]
    fn select_prefers_idle_alfa() {
        // Internal card advertises monitor but is carrying the host connection;
        // the Alfa is idle and monitor-capable.
        let alfa = test_iface(
            "wlan0",
            2,
            vec![InterfaceMode::Managed, InterfaceMode::Ap],
            Some("rtl8812au"),
            BusKind::Usb,
            None,
        );
        let internal = test_iface(
            "wlan1",
            3,
            vec![InterfaceMode::Managed, InterfaceMode::Monitor],
            Some("rtw89_8852be"),
            BusKind::Pci,
            Some("Flamingo"),
        );

        // Sanity: the heavy association penalty flips the ranking.
        assert!(alfa.monitor_score() > internal.monitor_score());

        let chosen = pick_best(vec![internal, alfa]).unwrap();
        assert_eq!(chosen.name(), "wlan0");
    }

    #[test]
    fn select_uses_internal_when_alfa_absent() {
        let internal = test_iface(
            "wlan0",
            2,
            vec![InterfaceMode::Managed, InterfaceMode::Monitor],
            Some("rtw89_8852be"),
            BusKind::Pci,
            None,
        );
        let chosen = pick_best(vec![internal]).unwrap();
        assert_eq!(chosen.name(), "wlan0");
    }

    #[test]
    fn pick_best_rejects_implausible() {
        let managed_only = test_iface(
            "wlan0",
            2,
            vec![InterfaceMode::Managed],
            Some("some_unknown_driver"),
            BusKind::Usb,
            None,
        );
        let err = pick_best(vec![managed_only]).unwrap_err();
        assert!(matches!(err, crate::Error::NoMonitorCapable { checked: 1 }));
    }

    #[test]
    fn pick_best_avoids_a_radio_already_in_monitor_mode() {
        // Another tool (airmon-ng, or an earlier rfmon run that persisted)
        // already has this radio in monitor mode. Commandeering it hijacks a
        // capture someone else is running, and the guard drops it back to
        // managed on teardown, killing that capture outright.
        //
        // Both radios score identically here, so the choice comes down to
        // whether selection considers the current mode at all. `busy` holds the
        // lower index, which wins the tie-break, so a pass means the mode was
        // actually taken into account rather than won by luck.
        let mut busy = test_iface(
            "wlan0",
            2,
            vec![InterfaceMode::Monitor],
            Some("ath9k"),
            BusKind::Usb,
            None,
        );
        busy.mode = InterfaceMode::Monitor;
        let idle = test_iface(
            "wlan1",
            3,
            vec![InterfaceMode::Monitor],
            Some("ath9k"),
            BusKind::Usb,
            None,
        );
        assert_eq!(
            busy.monitor_score(),
            idle.monitor_score(),
            "the fixture is only meaningful while the scores tie",
        );

        let chosen = pick_best(vec![busy, idle]).unwrap();
        assert_eq!(
            chosen.name(),
            "wlan1",
            "selection must not steal a radio that is already capturing",
        );
    }

    #[test]
    fn pick_best_rejects_a_lone_radio_already_in_monitor_mode() {
        // The ban is absolute, not a preference: with no alternative, selection
        // fails rather than taking the radio. rfmon keeps no ownership marker,
        // so it cannot tell its own leftover from a live capture, and getting it
        // wrong strands the interface in a state neither tool will clean up.
        let mut busy = test_iface(
            "wlan0",
            2,
            vec![InterfaceMode::Monitor],
            Some("ath9k"),
            BusKind::Usb,
            None,
        );
        busy.mode = InterfaceMode::Monitor;

        let err = pick_best(vec![busy]).unwrap_err();
        assert!(
            matches!(&err, crate::Error::AlreadyMonitor { iface } if iface == "wlan0"),
            "expected AlreadyMonitor naming wlan0, got {err:?}",
        );
    }

    #[test]
    fn pick_best_reports_the_radio_it_would_have_chosen() {
        // When every candidate is busy, the error names the best-scoring one:
        // the interface the caller has to free to make progress, not whichever
        // happened to be enumerated first.
        let mut weak = test_iface("wlan0", 2, vec![], Some("ath9k"), BusKind::Pci, None);
        weak.mode = InterfaceMode::Monitor;
        let mut strong = test_iface("wlan1", 3, vec![], Some("ath9k"), BusKind::Usb, None);
        strong.mode = InterfaceMode::Monitor;
        assert!(strong.monitor_score() > weak.monitor_score());

        let err = pick_best(vec![weak, strong]).unwrap_err();
        assert!(
            matches!(&err, crate::Error::AlreadyMonitor { iface } if iface == "wlan1"),
            "expected AlreadyMonitor naming the best candidate, got {err:?}",
        );
    }

    #[test]
    fn pick_best_reports_no_monitor_capable_before_already_monitor() {
        // A radio in monitor mode that is not a plausible candidate at all is
        // filtered by capability first, so the caller is told the real problem.
        let mut implausible =
            test_iface("wlan0", 2, vec![], Some("some_unknown"), BusKind::Pci, None);
        implausible.mode = InterfaceMode::Monitor;
        assert!(matches!(
            pick_best(vec![implausible]).unwrap_err(),
            crate::Error::NoMonitorCapable { checked: 1 }
        ));
    }

    #[test]
    fn pick_best_rejects_empty() {
        let err = pick_best(Vec::new()).unwrap_err();
        assert!(matches!(err, crate::Error::NoInterfaces));
    }

    // Build an interface carrying explicit bands for channel-resolution tests.
    fn iface_with_bands(bands: Vec<Band>) -> WirelessInterface {
        WirelessInterface {
            name: "wlan0".to_string(),
            index: 2,
            phy_index: 0,
            mac: MacAddr::ZERO,
            mode: InterfaceMode::Monitor,
            supported_modes: vec![InterfaceMode::Monitor],
            bands,
            driver: None,
            bus: BusKind::Usb,
            ssid: None,
        }
    }

    fn freq(mhz: u32, channel: u32, disabled: bool) -> Frequency {
        Frequency {
            mhz,
            channel: Some(channel),
            disabled,
            radar: false,
        }
    }

    #[test]
    fn resolve_frequency_maps_channel() {
        let iface = iface_with_bands(vec![
            Band {
                kind: BandKind::TwoGhz,
                frequencies: vec![freq(2412, 1, false), freq(2437, 6, false)],
            },
            Band {
                kind: BandKind::FiveGhz,
                frequencies: vec![freq(5180, 36, false)],
            },
        ]);
        let scope = BandScope::ExceptSixGhz;
        assert_eq!(resolve_frequency(&iface, 6, scope).unwrap(), 2437);
        assert_eq!(resolve_frequency(&iface, 36, scope).unwrap(), 5180);
    }

    #[test]
    fn resolve_frequency_rejects_an_absent_channel() {
        let iface = iface_with_bands(vec![Band {
            kind: BandKind::TwoGhz,
            frequencies: vec![freq(2412, 1, false), freq(2484, 14, true)],
        }]);
        // The device does not reach this frequency at all.
        assert!(matches!(
            resolve_frequency(&iface, 44, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::ChannelUnavailable { channel: 44, .. }
        ));
    }

    #[test]
    fn resolve_frequency_separates_disabled_from_absent() {
        let iface = iface_with_bands(vec![Band {
            kind: BandKind::TwoGhz,
            frequencies: vec![freq(2412, 1, false), freq(2484, 14, true)],
        }]);
        // The device has channel 14; the regulatory domain is what rules it out.
        // Reporting this as "not available" would send the operator looking for
        // different hardware to fix a setting.
        assert!(matches!(
            resolve_frequency(&iface, 14, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::ChannelDisabled { channel: 14, .. }
        ));
    }

    #[test]
    fn a_usable_channel_in_the_other_band_outranks_a_disabled_one() {
        // Channel 13 is disabled at 2.4 GHz but live at 6 GHz. `set_channel`
        // cannot reach the 6 GHz one, but `set_channel_6g` can, so the answer
        // that names a call which works now beats the one about a setting.
        let iface = iface_with_bands(vec![
            Band {
                kind: BandKind::TwoGhz,
                frequencies: vec![freq(2472, 13, true)],
            },
            Band {
                kind: BandKind::SixGhz,
                frequencies: vec![freq(6015, 13, false)],
            },
        ]);
        assert!(matches!(
            resolve_frequency(&iface, 13, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::WrongBand {
                channel: 13,
                alternative: "set_channel_6g",
                ..
            }
        ));
    }

    #[test]
    fn a_disabled_channel_in_the_other_band_is_not_worth_redirecting_to() {
        // Disabled on both sides: pointing at `set_channel_6g` would send the
        // caller to a call that fails the same way, so the regulatory domain is
        // the honest answer.
        let iface = iface_with_bands(vec![
            Band {
                kind: BandKind::TwoGhz,
                frequencies: vec![freq(2472, 13, true)],
            },
            Band {
                kind: BandKind::SixGhz,
                frequencies: vec![freq(6015, 13, true)],
            },
        ]);
        assert!(matches!(
            resolve_frequency(&iface, 13, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::ChannelDisabled { channel: 13, .. }
        ));
    }

    // A 6E adapter: every one of these channel numbers exists in two bands at
    // once. The scope carried by the entry point is what makes each unambiguous.
    fn sixe_iface() -> WirelessInterface {
        iface_with_bands(vec![
            Band {
                kind: BandKind::TwoGhz,
                frequencies: vec![freq(2412, 1, false), freq(2437, 6, false)],
            },
            Band {
                kind: BandKind::FiveGhz,
                frequencies: vec![freq(5180, 36, false), freq(5745, 149, false)],
            },
            Band {
                kind: BandKind::SixGhz,
                frequencies: vec![
                    freq(5955, 1, false),
                    freq(6695, 149, false),
                    freq(6135, 37, false),
                ],
            },
        ])
    }

    #[test]
    fn band_scope_separates_6e_collisions() {
        let iface = sixe_iface();

        // Channel 1 is 2.4 GHz here and 6 GHz there; 149 is 5 GHz UNII-3 and
        // 6 GHz. Both used to fail as ambiguous.
        assert_eq!(
            resolve_frequency(&iface, 1, BandScope::ExceptSixGhz).unwrap(),
            2412
        );
        assert_eq!(
            resolve_frequency(&iface, 1, BandScope::SixGhzOnly).unwrap(),
            5955
        );
        assert_eq!(
            resolve_frequency(&iface, 149, BandScope::ExceptSixGhz).unwrap(),
            5745
        );
        assert_eq!(
            resolve_frequency(&iface, 149, BandScope::SixGhzOnly).unwrap(),
            6695
        );
    }

    #[test]
    fn wrong_band_names_alternative() {
        let iface = sixe_iface();

        // 37 is a 6 GHz-only channel: don't claim the device cannot reach it.
        assert!(matches!(
            resolve_frequency(&iface, 37, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::WrongBand {
                channel: 37,
                alternative: "set_channel_6g",
                ..
            }
        ));
        // And the reverse: 36 is 5 GHz-only.
        assert!(matches!(
            resolve_frequency(&iface, 36, BandScope::SixGhzOnly).unwrap_err(),
            crate::Error::WrongBand {
                channel: 36,
                alternative: "set_channel",
                ..
            }
        ));
    }

    #[test]
    fn absent_channel_is_unavailable() {
        let iface = sixe_iface();
        assert!(matches!(
            resolve_frequency(&iface, 100, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::ChannelUnavailable { channel: 100, .. }
        ));
    }

    #[test]
    fn duplicate_frequencies_are_ambiguous() {
        // The residual case: one band reporting a channel number twice.
        let iface = iface_with_bands(vec![Band {
            kind: BandKind::FiveGhz,
            frequencies: vec![freq(5180, 36, false), freq(5200, 36, false)],
        }]);
        assert!(matches!(
            resolve_frequency(&iface, 36, BandScope::ExceptSixGhz).unwrap_err(),
            crate::Error::AmbiguousChannel { channel: 36, .. }
        ));
    }

    #[test]
    fn iface_name_enforces_kernel_limits() {
        assert!(validate_iface_name("mon0").is_ok());
        assert!(validate_iface_name("capture-5g").is_ok());
        assert!(matches!(
            validate_iface_name("").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
        assert!(matches!(
            validate_iface_name("this_name_is_way_too_long").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
        assert!(matches!(
            validate_iface_name("bad name").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
        // `:` separates alias interfaces (`eth0:1`); the kernel's
        // `dev_valid_name` rejects it alongside `/` and whitespace.
        assert!(matches!(
            validate_iface_name("mon:0").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
        // 15 characters is the limit (IFNAMSIZ is 16 including the NUL).
        assert!(validate_iface_name("123456789012345").is_ok());
        assert!(matches!(
            validate_iface_name("1234567890123456").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
        // `.` and `..` alias sysfs directory entries; the kernel rejects them.
        assert!(matches!(
            validate_iface_name(".").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
        assert!(matches!(
            validate_iface_name("..").unwrap_err(),
            crate::Error::InvalidInterfaceName { .. }
        ));
    }
}
