//! Linux nl80211 interface detection and mode switching.
//!
//! Talks to the kernel over nl80211 (generic netlink) to enumerate wireless
//! interfaces and the capabilities of their physical devices, and to switch an
//! interface between operating modes.
//!
//! Capabilities (supported modes and frequency bands) are properties of the
//! underlying physical device (the *wiphy*), not the netdev, so detection joins
//! an `NL80211_CMD_GET_INTERFACE` dump (`iw dev`) with an `NL80211_CMD_GET_WIPHY`
//! dump (`iw phy`) keyed by wiphy index. Each interface is then enriched with
//! the driver name and bus type read from sysfs.

use std::collections::BTreeMap;
use std::time::Duration;

use futures::stream::TryStreamExt;
use tokio::time::timeout;
use tracing::{debug, instrument, trace};
use wl_nl80211::{
    Nl80211Attr, Nl80211Band, Nl80211BandInfo, Nl80211BandType, Nl80211Channel,
    Nl80211ChannelWidth, Nl80211FrequencyInfo, Nl80211Handle, Nl80211IfMode, Nl80211InterfaceType,
};

use crate::errors::LinuxError;
use crate::interface::{
    Band, BandKind, BusKind, ChannelWidth, Frequency, InterfaceInfo, InterfaceMode, Tuning,
};
use crate::linux::{NETLINK_TIMEOUT, with_timeout};
use crate::{MacAddr, Result, channel_from_mhz};

/* Constants */

// Netlink dumps are local and normally return in milliseconds; this is a
// generous ceiling to bound the phase, not an expected wait.
const DUMP_TIMEOUT: Duration = Duration::from_secs(5);

/* Internal assembly types */

// One interface as read from an `NL80211_CMD_GET_INTERFACE` message, before it
// is joined with its wiphy's capabilities.
#[derive(Debug)]
struct RawInterface {
    name: String,
    index: u32,
    phy_index: u32,
    mac: MacAddr,
    mode: InterfaceMode,
    ssid: Option<String>,
}

// Capabilities of a single wiphy, accumulated across the (split) wiphy dump.
#[derive(Debug, Default)]
struct PhyAccum {
    supported_modes: Vec<InterfaceMode>,
    // Keyed by raw nl80211 band value so split-dump fragments of the same band
    // merge their frequency lists rather than producing duplicate bands.
    bands: BTreeMap<u16, (BandKind, Vec<Frequency>)>,
}

// Resolved capabilities for a single wiphy.
#[derive(Debug)]
struct PhyCaps {
    supported_modes: Vec<InterfaceMode>,
    bands: Vec<Band>,
}

impl PhyAccum {
    fn merge_band(&mut self, band: Nl80211Band) {
        let key = u16::from(band.kind);
        let kind = bandkind_from(band.kind);
        let entry = self.bands.entry(key).or_insert_with(|| (kind, Vec::new()));
        entry.1.extend(extract_frequencies(&band));
    }

    fn into_caps(self) -> PhyCaps {
        let bands = self
            .bands
            .into_values()
            .map(|(kind, frequencies)| Band { kind, frequencies })
            .collect();
        PhyCaps {
            supported_modes: self.supported_modes,
            bands,
        }
    }
}

/* Public backend operations */

/// Detect every wireless interface, joined with its physical device's
/// capabilities and enriched from sysfs.
#[instrument(level = "debug", err)]
pub(crate) async fn detect() -> Result<Vec<InterfaceInfo>> {
    let handle = open_handle()?;

    trace!("dumping nl80211 interfaces");
    let raw = timeout(DUMP_TIMEOUT, collect_interfaces(&handle))
        .await
        .map_err(|_| LinuxError::Timeout {
            command: "get_interface",
            timeout_ms: DUMP_TIMEOUT.as_millis() as u64,
        })??;
    trace!(count = raw.len(), "dumped interfaces");

    trace!("dumping nl80211 wiphy capabilities");
    let phys = timeout(DUMP_TIMEOUT, collect_phys(&handle))
        .await
        .map_err(|_| LinuxError::Timeout {
            command: "get_wiphy",
            timeout_ms: DUMP_TIMEOUT.as_millis() as u64,
        })??;
    trace!(count = phys.len(), "dumped wiphy devices");

    let caps: BTreeMap<u32, PhyCaps> = phys.into_iter().map(|(k, v)| (k, v.into_caps())).collect();
    let interfaces = assemble(raw, &caps);

    debug!(count = interfaces.len(), "detected wireless interfaces");
    Ok(interfaces)
}

/// Switch an interface into a new operating mode.
///
/// Applies the classic sequence drivers expect: bring the link down
/// (rtnetlink), change the interface type (nl80211 `SET_INTERFACE`), then bring
/// the link back up. Most drivers, including the Realtek USB adapters, refuse
/// a type change while the link is up. Requires `CAP_NET_ADMIN`.
#[instrument(level = "debug", skip(iface), fields(iface = %iface.name(), index = iface.index()), err)]
pub(crate) async fn set_mode(iface: &InterfaceInfo, mode: InterfaceMode) -> Result<()> {
    let name = iface.name();
    let index = iface.index();

    with_timeout("set interface mode", NETLINK_TIMEOUT, async move {
        // 1. Bring the link administratively down (rtnetlink).
        let (rt_connection, rt_handle, _) =
            rtnetlink::new_connection().map_err(|source| LinuxError::NetlinkConnect {
                kind: "rtnetlink",
                phase: "connect",
                source,
            })?;
        tokio::spawn(rt_connection);

        set_link(&rt_handle, index, false)
            .await
            .map_err(|source| LinuxError::LinkSet {
                op: "down",
                iface: name.to_string(),
                source,
            })?;

        // 2. Change the interface type. If this fails, bring the link back up
        //    before returning so we never leave the interface administratively down.
        if let Err(error) = set_iftype(name, index, mode_to_iftype(mode)).await {
            let _ = set_link(&rt_handle, index, true).await;
            return Err(error.into());
        }

        // 3. Bring the link back up in the new mode.
        set_link(&rt_handle, index, true)
            .await
            .map_err(|source| LinuxError::LinkSet {
                op: "up",
                iface: name.to_string(),
                source,
            })?;

        debug!(mode = %mode, "set interface mode");
        Ok(())
    })
    .await
}

/// Set the operating channel of an interface over nl80211.
///
/// Issues `SET_WIPHY` carrying the interface index, the center frequency in MHz,
/// and the channel width. For 40 MHz the secondary channel is expressed as the
/// segment center frequency (primary ± 10 MHz). The interface should already be
/// up and in monitor mode. Requires `CAP_NET_ADMIN`.
#[instrument(level = "debug", err)]
pub(crate) async fn set_channel(
    index: u32,
    name: &str,
    freq_mhz: u32,
    width: ChannelWidth,
) -> Result<()> {
    with_timeout("set interface channel", NETLINK_TIMEOUT, async move {
        let handle = open_handle()?;

        let (nl_width, center1) = match width {
            ChannelWidth::Mhz20 => (Nl80211ChannelWidth::NoHt20, None),
            ChannelWidth::Mhz40Above => (Nl80211ChannelWidth::Mhz(40), Some(freq_mhz + 10)),
            ChannelWidth::Mhz40Below => (Nl80211ChannelWidth::Mhz(40), Some(freq_mhz - 10)),
        };

        let mut builder = Nl80211Channel::new(index)
            .frequency(freq_mhz)
            .channel_width(nl_width);
        if let Some(center) = center1 {
            builder = builder.center_frequency(center);
        }

        let mut stream = handle
            .wireless_physic()
            .set(builder.build())
            .execute()
            .await;
        while stream
            .try_next()
            .await
            .map_err(|source| LinuxError::SetChannel {
                iface: name.to_string(),
                source,
            })?
            .is_some()
        {}

        debug!(iface = name, freq_mhz, ?width, "set interface channel");
        Ok(())
    })
    .await
}

/// Rename an interface over rtnetlink.
///
/// The kernel only allows a rename while the link is administratively down, so
/// this brings it down, renames, and brings it back up. The interface index is
/// unchanged by a rename. Requires `CAP_NET_ADMIN`.
///
/// **An error does not mean the name is unchanged.** The rename is applied
/// before the link is brought back up, and the rename error is reported first,
/// so a failed bring-up surfaces as `LinkSet` on an interface that *did* get
/// renamed. Callers rolling back must address the interface by index and attempt
/// the reverse rename regardless; it is a no-op when the name never changed.
#[instrument(level = "debug", err)]
pub(crate) async fn rename(index: u32, old: &str, new: &str) -> Result<()> {
    with_timeout("rename interface", NETLINK_TIMEOUT, async move {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|source| LinuxError::NetlinkConnect {
                kind: "rtnetlink",
                phase: "connect",
                source,
            })?;
        tokio::spawn(connection);

        set_link(&handle, index, false)
            .await
            .map_err(|source| LinuxError::LinkSet {
                op: "down",
                iface: old.to_string(),
                source,
            })?;

        let message = rtnetlink::LinkUnspec::new_with_index(index)
            .name(new.to_string())
            .build();
        let rename_result = handle.link().set(message).execute().await;

        // Bring the link back up regardless of whether the rename took, so we
        // never strand the interface down.
        let up_result = set_link(&handle, index, true).await;

        rename_result.map_err(|source| LinuxError::Rename {
            old: old.to_string(),
            new: new.to_string(),
            source,
        })?;
        up_result.map_err(|source| LinuxError::LinkSet {
            op: "up",
            iface: new.to_string(),
            source,
        })?;

        debug!(old, new, "renamed interface");
        Ok(())
    })
    .await
}

/// Read an interface's current operating mode by index, over nl80211.
///
/// Used to empirically confirm a mode change actually took effect. Bounded by
/// [`NETLINK_TIMEOUT`] like every other control operation: this runs on the
/// rollback path inside `enter`, which the blocking `Drop` can reach, so an
/// unbounded read here would hang teardown on a wedged driver.
pub(crate) async fn read_mode(index: u32) -> Result<InterfaceMode> {
    with_timeout("read interface mode", NETLINK_TIMEOUT, async move {
        let handle = open_handle()?;
        // A non-empty attribute set makes this a single get (no dump) for one iface.
        let mut stream = handle
            .interface()
            .get(vec![Nl80211Attr::IfIndex(index)])
            .execute()
            .await;

        while let Some(msg) = stream.try_next().await.map_err(|source| LinuxError::Dump {
            command: "get_interface",
            source,
        })? {
            for attr in msg.payload.attributes {
                if let Nl80211Attr::IfType(value) = attr {
                    return Ok(mode_from_iftype(value));
                }
            }
        }

        Err(crate::Error::NotFound {
            name: format!("if_index {index}"),
            available: String::new(),
        })
    })
    .await
}

/// Read an interface's current center frequency (MHz) by index, over nl80211.
///
/// Used to empirically confirm a channel change took effect, the same
/// "adapters lie" defense [`read_mode`] provides for mode switches. Every field
/// of the returned [`Tuning`] is `None` when the interface exists but is
/// not tuned; `NotFound` means no interface has the index. Bounded by
/// [`NETLINK_TIMEOUT`], for the same reason [`read_mode`] is.
///
/// All three attributes are read, not just the primary frequency: a driver that
/// accepts a 40 MHz request and falls back to 20 lands on the right frequency,
/// so frequency alone cannot tell a honoured set from a silently narrowed one.
pub(crate) async fn read_channel(index: u32) -> Result<Tuning> {
    with_timeout("read interface channel", NETLINK_TIMEOUT, async move {
        let handle = open_handle()?;
        // A non-empty attribute set makes this a single get (no dump) for one iface.
        let mut stream = handle
            .interface()
            .get(vec![Nl80211Attr::IfIndex(index)])
            .execute()
            .await;

        let mut found = false;
        // Start from untuned and fill in whatever the kernel actually reports:
        // a driver may return any subset of the three attributes.
        let mut state = Tuning::UNTUNED;
        while let Some(msg) = stream.try_next().await.map_err(|source| LinuxError::Dump {
            command: "get_interface",
            source,
        })? {
            found = true;
            for attr in msg.payload.attributes {
                match attr {
                    Nl80211Attr::WiphyFreq(value) => state.freq_mhz = Some(value),
                    Nl80211Attr::ChannelWidth(value) => state.width_mhz = width_mhz(value),
                    Nl80211Attr::CenterFreq1(value) => state.center_mhz = Some(value),
                    _ => {}
                }
            }
        }

        if found {
            Ok(state)
        } else {
            Err(crate::Error::NotFound {
                name: format!("if_index {index}"),
                available: String::new(),
            })
        }
    })
    .await
}

/* Free functions */

// Map an nl80211 iftype (from GET_INTERFACE) to our neutral mode.
fn mode_from_iftype(value: Nl80211InterfaceType) -> InterfaceMode {
    match value {
        Nl80211InterfaceType::Station => InterfaceMode::Managed,
        Nl80211InterfaceType::Monitor => InterfaceMode::Monitor,
        Nl80211InterfaceType::Ap => InterfaceMode::Ap,
        Nl80211InterfaceType::Adhoc => InterfaceMode::Adhoc,
        Nl80211InterfaceType::MeshPoint => InterfaceMode::MeshPoint,
        other => InterfaceMode::Other(other.into()),
    }
}

// Map an nl80211 supported-iftype (from GET_WIPHY) to our neutral mode.
fn mode_from_ifmode(value: Nl80211IfMode) -> InterfaceMode {
    match value {
        Nl80211IfMode::Station => InterfaceMode::Managed,
        Nl80211IfMode::Monitor => InterfaceMode::Monitor,
        Nl80211IfMode::Ap => InterfaceMode::Ap,
        Nl80211IfMode::Adhoc => InterfaceMode::Adhoc,
        Nl80211IfMode::MeshPoint => InterfaceMode::MeshPoint,
        other => InterfaceMode::Other(u16::from(other) as u32),
    }
}

// The nl80211 iftype to request for a mode via `SET_INTERFACE`.
fn mode_to_iftype(mode: InterfaceMode) -> Nl80211InterfaceType {
    match mode {
        InterfaceMode::Managed => Nl80211InterfaceType::Station,
        InterfaceMode::Monitor => Nl80211InterfaceType::Monitor,
        InterfaceMode::Ap => Nl80211InterfaceType::Ap,
        InterfaceMode::Adhoc => Nl80211InterfaceType::Adhoc,
        InterfaceMode::MeshPoint => Nl80211InterfaceType::MeshPoint,
        InterfaceMode::Other(v) => Nl80211InterfaceType::from(v),
    }
}

// Normalise an nl80211 channel width to plain MHz. `NoHt20` and `Mhz(20)` are
// both 20 MHz as far as verification is concerned; `Other` is a width this
// binding does not name, which we cannot compare against and so report as
// unknown.
fn width_mhz(value: Nl80211ChannelWidth) -> Option<u32> {
    match value {
        Nl80211ChannelWidth::NoHt20 => Some(20),
        Nl80211ChannelWidth::Mhz(mhz) => Some(mhz),
        Nl80211ChannelWidth::Mhz80Plus80 => Some(80),
        Nl80211ChannelWidth::Other(_) => None,
    }
}

fn bandkind_from(value: Nl80211BandType) -> BandKind {
    match value {
        Nl80211BandType::Band2GHz => BandKind::TwoGhz,
        Nl80211BandType::Band5GHz => BandKind::FiveGhz,
        Nl80211BandType::Band6GHz => BandKind::SixGhz,
        Nl80211BandType::Band60GHz => BandKind::SixtyGhz,
        other => BandKind::Other(other.into()),
    }
}

// Toggle an interface's administrative link state (up/down) over rtnetlink.
async fn set_link(
    handle: &rtnetlink::Handle,
    index: u32,
    up: bool,
) -> std::result::Result<(), rtnetlink::Error> {
    let link = rtnetlink::LinkUnspec::new_with_index(index);
    let message = if up { link.up() } else { link.down() }.build();
    handle.link().set(message).execute().await
}

// Change an interface's nl80211 iftype (`SET_INTERFACE`), draining the ACK.
async fn set_iftype(
    iface: &str,
    index: u32,
    iftype: Nl80211InterfaceType,
) -> std::result::Result<(), LinuxError> {
    let handle = open_handle()?;
    let mut stream = handle
        .interface()
        .set(vec![
            Nl80211Attr::IfIndex(index),
            Nl80211Attr::IfType(iftype),
        ])
        .execute()
        .await;

    while stream
        .try_next()
        .await
        .map_err(|source| LinuxError::SetMode {
            iface: iface.to_string(),
            source,
        })?
        .is_some()
    {}
    Ok(())
}

// Open a fresh nl80211 handle and spawn its connection task onto the runtime.
fn open_handle() -> std::result::Result<Nl80211Handle, LinuxError> {
    let (connection, handle, _) =
        wl_nl80211::new_connection().map_err(|source| LinuxError::NetlinkConnect {
            kind: "nl80211",
            phase: "connect",
            source,
        })?;
    tokio::spawn(connection);
    Ok(handle)
}

// Dump `NL80211_CMD_GET_INTERFACE` (equivalent to `iw dev`).
async fn collect_interfaces(
    handle: &Nl80211Handle,
) -> std::result::Result<Vec<RawInterface>, LinuxError> {
    let mut stream = handle.interface().get(Vec::new()).execute().await;
    let mut interfaces = Vec::new();

    while let Some(msg) = stream.try_next().await.map_err(|source| LinuxError::Dump {
        command: "get_interface",
        source,
    })? {
        let mut name = None;
        let mut index = None;
        let mut phy_index = None;
        let mut mac = None;
        let mut mode = None;
        let mut ssid = None;

        for attr in msg.payload.attributes {
            match attr {
                Nl80211Attr::IfName(value) => name = Some(value),
                Nl80211Attr::IfIndex(value) => index = Some(value),
                Nl80211Attr::Wiphy(value) => phy_index = Some(value),
                Nl80211Attr::Mac(value) => mac = Some(MacAddr(value)),
                Nl80211Attr::IfType(value) => mode = Some(mode_from_iftype(value)),
                // Present only when the interface is currently associated.
                Nl80211Attr::Ssid(value) => ssid = Some(value),
                _ => {}
            }
        }

        // A real netdev always carries ifindex, ifname, and wiphy. Non-netdev
        // entities (e.g. P2P-device) lack ifindex and are skipped.
        let (Some(index), Some(name), Some(phy_index)) = (index, name, phy_index) else {
            trace!("skipping nl80211 interface without ifindex/ifname/wiphy");
            continue;
        };

        interfaces.push(RawInterface {
            name,
            index,
            phy_index,
            mac: mac.unwrap_or(MacAddr::ZERO),
            mode: mode.unwrap_or(InterfaceMode::Other(0)),
            ssid,
        });
    }

    Ok(interfaces)
}

// Dump `NL80211_CMD_GET_WIPHY` (equivalent to `iw phy`), aggregating the split
// dump into one accumulator per wiphy index.
async fn collect_phys(
    handle: &Nl80211Handle,
) -> std::result::Result<BTreeMap<u32, PhyAccum>, LinuxError> {
    let mut stream = handle.wireless_physic().get().execute().await;
    let mut phys: BTreeMap<u32, PhyAccum> = BTreeMap::new();

    while let Some(msg) = stream.try_next().await.map_err(|source| LinuxError::Dump {
        command: "get_wiphy",
        source,
    })? {
        let mut index = None;
        let mut modes = None;
        let mut bands = None;

        for attr in msg.payload.attributes {
            match attr {
                Nl80211Attr::Wiphy(value) => index = Some(value),
                Nl80211Attr::SupportedIftypes(value) => modes = Some(value),
                Nl80211Attr::WiphyBands(value) => bands = Some(value),
                _ => {}
            }
        }

        let Some(index) = index else {
            continue;
        };
        let entry = phys.entry(index).or_default();

        if let Some(modes) = modes {
            entry.supported_modes = modes.into_iter().map(mode_from_ifmode).collect();
        }
        if let Some(bands) = bands {
            for band in bands {
                entry.merge_band(band);
            }
        }
    }

    Ok(phys)
}

// Pull the usable frequencies out of one band's nl80211 attributes.
fn extract_frequencies(band: &Nl80211Band) -> Vec<Frequency> {
    let mut frequencies = Vec::new();

    for info in &band.info {
        let Nl80211BandInfo::Freqs(freqs) = info else {
            continue;
        };

        for freq in freqs {
            let mut mhz = None;
            let mut disabled = false;
            let mut radar = false;

            for item in &freq.info {
                match item {
                    Nl80211FrequencyInfo::Freq(value) => mhz = Some(*value),
                    Nl80211FrequencyInfo::Disabled => disabled = true,
                    Nl80211FrequencyInfo::Radar => radar = true,
                    _ => {}
                }
            }

            if let Some(mhz) = mhz {
                frequencies.push(Frequency {
                    mhz,
                    channel: channel_from_mhz(mhz),
                    disabled,
                    radar,
                });
            }
        }
    }

    frequencies
}

// Join raw interfaces with their wiphy capabilities, and enrich each with the
// driver/bus read from sysfs. Multiple interfaces may share a wiphy, so
// capabilities are cloned rather than moved.
fn assemble(raw: Vec<RawInterface>, caps: &BTreeMap<u32, PhyCaps>) -> Vec<InterfaceInfo> {
    raw.into_iter()
        .map(|iface| {
            let (supported_modes, bands) = match caps.get(&iface.phy_index) {
                Some(phy) => (phy.supported_modes.clone(), phy.bands.clone()),
                None => (Vec::new(), Vec::new()),
            };
            let (driver, bus) = read_phy_sysfs(iface.phy_index);
            InterfaceInfo {
                name: iface.name,
                index: iface.index,
                phy_index: iface.phy_index,
                mac: iface.mac,
                mode: iface.mode,
                supported_modes,
                bands,
                driver,
                bus,
                ssid: iface.ssid,
            }
        })
        .collect()
}

// Read the bound driver name and bus type for a wiphy from sysfs.
//
// These are metadata reads against the in-memory sysfs pseudo-filesystem
// (`/sys/class/ieee80211/phyN/device/...`), not disk I/O, so they are cheap
// enough to run inline. Any missing/unreadable link yields `None`/`Other`
// rather than an error; driver/bus are advisory selection hints.
//
// Run inline rather than under `spawn_blocking`, despite being a synchronous
// filesystem call in an async context: a sysfs readlink resolves from memory in
// microseconds and never touches a disk, so the executor is not stalled, and
// the hop to a blocking thread would cost more than the read itself.
fn read_phy_sysfs(phy_index: u32) -> (Option<String>, BusKind) {
    let base = format!("/sys/class/ieee80211/phy{phy_index}/device");

    let file_name = |path: String| {
        std::fs::read_link(path)
            .ok()
            .and_then(|target| target.file_name().map(|n| n.to_string_lossy().into_owned()))
    };

    let driver = file_name(format!("{base}/driver"));
    let bus = match file_name(format!("{base}/subsystem")).as_deref() {
        Some("usb") => BusKind::Usb,
        Some("pci") => BusKind::Pci,
        _ => BusKind::Other,
    };

    (driver, bus)
}

/* Tests */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_mode_maps_station_to_managed() {
        assert_eq!(
            mode_from_iftype(Nl80211InterfaceType::Station),
            InterfaceMode::Managed
        );
        assert_eq!(
            mode_from_iftype(Nl80211InterfaceType::Monitor),
            InterfaceMode::Monitor
        );
    }

    #[test]
    fn interface_mode_preserves_unknown_iftypes() {
        assert_eq!(
            mode_from_iftype(Nl80211InterfaceType::Nan),
            InterfaceMode::Other(12)
        );
    }

    #[test]
    fn band_kind_maps_from_nl80211() {
        assert_eq!(bandkind_from(Nl80211BandType::Band2GHz), BandKind::TwoGhz);
        assert_eq!(bandkind_from(Nl80211BandType::Band6GHz), BandKind::SixGhz);
    }

    #[test]
    fn assemble_shares_phy_caps_across_interfaces() {
        let mut caps = BTreeMap::new();
        caps.insert(
            0u32,
            PhyCaps {
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
            },
        );

        let raw = vec![
            RawInterface {
                name: "wlan0".to_string(),
                index: 3,
                phy_index: 0,
                mac: MacAddr::ZERO,
                mode: InterfaceMode::Managed,
                ssid: None,
            },
            RawInterface {
                name: "wlan0mon".to_string(),
                index: 4,
                phy_index: 0,
                mac: MacAddr::ZERO,
                mode: InterfaceMode::Monitor,
                ssid: None,
            },
        ];

        let interfaces = assemble(raw, &caps);
        assert_eq!(interfaces.len(), 2);
        assert!(interfaces.iter().all(|i| i.supports_monitor()));
        assert!(interfaces.iter().all(|i| i.bands().len() == 1));
        assert_eq!(interfaces[1].frequencies().count(), 1);
    }
}
