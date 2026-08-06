# rfmon

A Linux library/CLI to streamline 802.11 monitor mode with clean recovery, and without killing network daemons.

## Why

The `aircrack-ng` suite, while battle-tested, has a crude way of putting devices in monitor mode for packet sniffing in that it kills NetworkManager and wpa_supplicant to stop them from yanking the interfaces back into managed mode mid-operation. These require manual restarting, and additionally stop all other interfaces on the device from associating with a network while down. `rfmon` instead speaks directly to these daemons, telling them to release control over the specific interface so connectivity can be maintained on the device without having them interfere with operation. On a host running neither, or with the `dbus` feature off, it falls back to the raw nl80211 and rtnetlink switch.

`rfmon` additionally offers built-in restoration for any unwinding shutdown. All `start_*` calls that set an interface in monitor mode yield a `MonitorGuard`, which restores the device to managed mode and to the control of the network daemons when it is dropped. `guard.restore().await` does the same explicitly and returns a `Result`. Where no guard is in hand, `stop_monitor(iface)` and `sudo rfmon stop_monitor <iface>` repair an interface by name.

Every mode and channel change is read back from the kernel and confirmed, so a driver that accepts a request and quietly ignores it yields an error rather than a silent failure or a wrong channel capture. `rfmon` will also refuse to bring up any interface already in monitor mode, rather than hijack a capture another tool is running.

## API & Usage

| Call | Does |
|---|---|
| `start_monitor()` | Select the best radio, enter monitor mode. Reuses the same interface name.|
| `start_monitor_on(iface)` | Enter monitor mode on a named interface. |
| `start_monitor_as(iface, new)` | Enter monitor mode, then rename the interface. |
| `.on_channel(chan)` | On any of the three above: park on a channel as part of the same call. |
| `set_channel(iface, chan)` | Tune a 2.4 or 5 GHz channel. Takes `.with_width(..)`. |
| `set_channel_6g(iface, chan)` | Tune a 6 GHz channel. A separate call because 6 GHz numbering restarts at 1 and collides with 2.4 and 5 GHz.|
| `stop_monitor(iface)` | Restore one interface to managed networking, by name. |
| `stop_all_monitors()` | Restore every monitor mode interface, best effort. |
| `InterfaceInfo::detect()` | Enumerate every interface with its capabilities: modes, bands, channels. |
| `InterfaceInfo::lookup(iface)` | The same enumeration, filtered to one name. |

The three `start_*` calls return a `MonitorBuilder`, which does nothing until awaited and then yields the `MonitorGuard` that owns the session.

A monitor interface can be programmatically created several ways:

```rust,ignore
use rfmon::ChannelWidth;

let mon1 = rfmon::start_monitor().await?;

// persist() hands the session over to the interface name, leaving no guard to drop
rfmon::start_monitor_on("wlan1").on_channel(36).await?.persist();

let mon3 = rfmon::start_monitor_as("wlan2", "mon0")
    .on_channel(149)
    .with_width(ChannelWidth::Mhz40Above)
    .await?;
```

and can be managed again just as easily:

```rust,ignore
mon1.restore().await?;
rfmon::stop_monitor("wlan1").await?;
// Upon going out of scope, "mon0" will automatically restore to "wlan2"
```

## Install

```toml
[dependencies]
rfmon = "0.1"
```

CLI: `cargo install rfmon --features cli`

Linux only. Anything that changes an interface needs `CAP_NET_ADMIN`, root in practice; enumeration needs no privileges.

## Licence

MIT or Apache-2.0, at your option.