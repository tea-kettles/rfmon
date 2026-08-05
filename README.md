# rfmon

Puts a Wi-Fi interface into 802.11 monitor mode on Linux and takes it back out again easily, safely, automatically, and not destructively like methods that require ```airmon-ng check kill``` to stop net management daemons. Library plus CLI.

The interface is switched in place, so no `wlan0mon` clone appears (but it can if you want it to). The switch is read back and verified in both directions, since a number of adapters accept the request without honoring it, and on the way out too, so a driver that never really left monitor mode cannot be reported as restored. Whatever currently owns the interface (NetworkManager, wpa_supplicant, or nothing at all) is released first and handed back on restore, so the same code path works on a desktop and on a headless box.

`rfmon` does not read or write frames. It produces a monitor mode interface parked on a known channel, which is precisely the input `pcap`, `libpnet`, or a raw `AF_PACKET` socket expect. See [Scope](#scope).

## Platform support

| Platform | State |
|---|---|
| Linux | Implemented over nl80211 and rtnetlink, with NetworkManager and wpa_supplicant coordination. |
| Windows | Compile only stub that'll be filled out later. Native Windows exposes no 802.11 monitor mode, so calls return `WindowsError::Unsupported`. An Npcap backed backend is the intended path. |
| Mac | Planned but no promises |

Every operation that changes an interface requires `CAP_NET_ADMIN`, most easily obtained by running as root. Enumeration (`WirelessInterface::detect` and the CLI's `list`) reads the nl80211 dumps any user can read, so it needs no privileges.

## Install

Library:

```toml
[dependencies]
rfmon = "0.1"
```

CLI, feature gated so library users do not pull in a tracing subscriber:

```sh
cargo install --path . --features cli
# or, in tree:
cargo build --features cli   # -> target/debug/rfmon
```

## Quickstart

```rust
#[tokio::main]
async fn main() -> rfmon::Result<()> {
    // Select the best monitor capable radio and enter monitor mode.
    let mon = rfmon::start_monitor().await?;

    // Park on a channel. 2.4 GHz is 1 to 14, 5 GHz is 32 to 177. Tuning through
    // the guard reuses the interface it resolved, so hops are cheap and verified.
    mon.set_channel(36).await?;

    // Capture raw 802.11 frames on `mon.name()` with pcap or AF_PACKET.

    // Restore managed networking. Also happens on drop.
    mon.restore().await?;
    Ok(())
}
```

## API

| Call | Does |
|---|---|
| `start_monitor()` | Select the best radio, enter monitor mode. |
| `start_monitor_on(iface)` | Enter monitor mode on a named interface. |
| `start_monitor_as(iface, new)` | Enter monitor mode, then rename the interface. |
| `set_channel(iface, chan)` | Tune a 2.4 or 5 GHz channel. Takes `.with_width(..)`. |
| `set_channel_6g(iface, chan)` | Tune a 6 GHz channel. Same builder, different band. |
| `stop_monitor(iface)` | Restore one interface to managed networking, by name. |
| `stop_all_monitors()` | Restore every monitor mode interface, best effort. |
| `WirelessInterface::detect()` | Enumerate interfaces and their capabilities: modes, bands, channels. |

The three `start_*` calls return a [`MonitorGuard`](#cleanup). `stop_monitor` and `stop_all_monitors` are stateless and name based, for the cases a guard cannot cover. Everything is fallible and returns `Result`; nothing in the library panics on hardware state.

### Interface selection

`start_monitor` scores every interface and takes the best capture candidate. It favours a known monitor capable USB adapter, and penalises heavily any interface currently carrying a live connection, so it will not steal your uplink while another radio can do the job. Selection is confirmed empirically: the chosen device only counts once monitor mode has been entered and read back.

Candidates are tried in ranked order until one is confirmed. Monitor capability is a prediction until it is tried, so a radio that refuses the switch hands off to the next one rather than failing the whole call; each attempt rolls back before the next.

An interface **already in monitor mode is never taken**. Something else put it there, and `rfmon` keeps no ownership marker, so it cannot tell its own leftover from another tool's live capture. Taking one hijacks that capture, and restoring it to managed mode afterwards breaks the other tool's teardown: `airmon-ng stop` looks for monitor mode to identify what it created, and refuses when it finds a managed interface, leaving a state neither tool will clean up. Clear it deliberately with `stop_monitor` first.

This is a refusal, not a preference. `start_monitor_on` and `start_monitor_as` bypass scoring, so they return `AlreadyMonitor` rather than proceeding. Auto-selection only fails if *every* candidate is busy; one radio in monitor mode does not block the others, it is skipped with a warning naming it, which is also the hint you need when the real cause is a previous session that was never stopped.

### Coordination with the host

Release and handback are best effort and layered:

1. NetworkManager, via `org.freedesktop.NetworkManager`, if it is running.
2. wpa_supplicant, via `fi.w1.wpa_supplicant1`, if it is running. Released in addition to NetworkManager, since a standalone supplicant will otherwise revert the mode underneath you.
3. Neither, on a minimal or headless host. Just the raw nl80211 and rtnetlink switch.

A missing service, or the absence of a system D-Bus altogether, is detected and skipped rather than treated as an error.

This coordination lives behind the `dbus` feature, which is **on by default**. A host that runs neither NetworkManager nor wpa_supplicant needs none of it, so a minimal build can drop it, and with it roughly half the dependency tree (all of `zbus`):

```toml
rfmon = { version = "0.1", default-features = false }
```

With `dbus` off, entering and leaving monitor mode is the raw nl80211/rtnetlink switch, exactly the third case above, made unconditional.

### Channels

`set_channel` takes a channel number rather than a frequency. The frequency is resolved against the channels the device actually reports, so asking for one it does not support yields a `ChannelUnavailable` error rather than a silent no-op.

A channel the device *has* but the regulatory domain disables is a different error, `ChannelDisabled`, because it has a different fix. "Not available" reads as a hardware limit and sends you looking for another adapter; the usual cause is a regulatory domain narrower than the radio (2.4 GHz channels 12 to 14 outside the EU and Japan, or most of 5 GHz on an unset domain), which is a setting. `rfmon` does not change it: the regulatory domain is system wide, with a lifetime unrelated to any capture session, so it sits outside what this library manages. `iw reg get` reports it and `iw reg set` changes it.

Channel numbers are not unique across bands. 6 GHz numbers 1, 5, 9 and 13 collide with 2.4 GHz, and 149 through 177 collide with 5 GHz UNII-3, so on a Wi-Fi 6E adapter, `set_channel(1)` has two valid answers. Rather than make the band an argument you can forget to pass, there are two calls and the band is part of the name:

```rust
rfmon::set_channel(iface, 1).await?;      // 2.4 GHz ch 1  = 2412 MHz
rfmon::set_channel_6g(iface, 1).await?;   // 6 GHz   ch 1  = 5955 MHz

rfmon::set_channel(iface, 149).await?;    // 5 GHz   ch 149 = 5745 MHz
rfmon::set_channel_6g(iface, 149).await?; // 6 GHz   ch 149 = 6695 MHz
```

`set_channel` covers 2.4 GHz (1 to 14) and 5 GHz (32 to 177), which do not overlap each other, so the number alone still picks the band within it. `set_channel_6g` covers 6 GHz only (1, 5, 9 … 233; centre frequency 5950 + 5 × channel MHz) and needs a 6E capable adapter. Get it backwards and the error names the call you wanted:

```
channel 37 on 'wlan0' is in another band; use set_channel_6g() to tune it
```

Width defaults to 20 MHz, which carries all management and EAPOL traffic. Use `.with_width(ChannelWidth::Mhz40Above)` or `Mhz40Below` for wide capture; the builder is the same for both calls.

Every set is read back and verified, for the same reason the mode switch is: a driver can accept `SET_WIPHY` and sit on a different frequency, so a set that did not take yields a `ChannelVerifyFailed` error rather than a silent wrong-channel capture.

The width is verified too, separately. A driver that accepts a 40 MHz request and quietly falls back to 20 lands on exactly the right frequency, so checking the frequency alone cannot tell an honoured set from a narrowed one, and the resulting capture looks correct while seeing half the channel. That case yields `WidthVerifyFailed`. For 40 MHz the check covers which side the secondary sits on, since `HT40+` and `HT40-` differ only by their segment centre.

The free `set_channel(name, …)` enumerates the system to resolve the name each call. If you hold a guard, and `start_*` always returns one, tune through it instead: it reuses the interface it already resolved, so a channel hop is a single verified `SET_WIPHY` rather than a re-scan of every radio on the box. This is the path to use for a hopping loop:

```rust
let mon = rfmon::start_monitor().await?;
for channel in [1, 6, 11] {
    mon.set_channel(channel).await?;   // no re-enumeration
    // ... dwell and capture ...
}
mon.set_channel_6g(37).await?;         // 6 GHz counterpart, same guard
```

### Cleanup

The `start_*` calls return a guard that owns the session:

- `guard.restore().await` is the reliable teardown. It renames back where applicable, restores managed networking, and returns a `Result`.
- Drop is the safety net. Rust has no async drop, so the restore is run to completion on a dedicated thread and blocks. This covers normal scope exit, `?` early returns, task cancellation, and panic unwinding.
- `guard.persist()` cancels auto restore and leaves the interface in monitor mode. This is what the CLI uses.

### Recovery

Drop cannot cover `panic = "abort"`, `process::exit` or `abort`, Ctrl-C and SIGTERM (the default handlers do not unwind), SIGKILL, OOM, or loss of power. No in process mechanism can. `stop_monitor(name)` and `stop_all_monitors()` exist for exactly this: stateless repair of an interface that a dead process left stranded, run on next startup or by hand from the CLI.

The same tools cover interference. Do not run `rfmon` alongside `airmon-ng`, or any other supplicant grabbing the same device, as the other tool can revert the mode underneath you. If it does, `rfmon stop_monitor all` or `rfmon reset` will put things right.

## CLI

```
rfmon [-v] start_monitor [<iface>]          enter monitor mode, auto selecting if no iface given
rfmon [-v] start_monitor_as <iface> <new>   enter monitor mode, then rename to <new>
rfmon [-v] stop_monitor <iface>             restore managed networking by name
rfmon [-v] stop_monitor all                 restore every monitor mode interface
rfmon [-v] reset                            stop all monitors, restart wpa_supplicant and NetworkManager
rfmon [-v] list                             show interfaces, capabilities and usable channels
```

`list` is the read-only one: it prints each interface with its driver, bus, MAC, monitor capability, and the channels the regulatory domain actually leaves usable, including whether an interface is already in monitor mode, which is what makes `rfmon` refuse to take it.

The `start_*` commands leave the interface in monitor mode after the process exits, as airmon does, so pair them with `stop_monitor` to undo. `reset` is the blunt instrument for a system wide mess. `-v` raises logging to debug level; output is plain `tracing` to the console.

```sh
sudo rfmon start_monitor wlan0     # INFO monitor mode iface=wlan0
sudo tcpdump -i wlan0 -w cap.pcap  # capture with the tool of your choice
sudo rfmon stop_monitor wlan0      # INFO managed mode iface=wlan0

sudo rfmon reset                   # everything back to managed, services restarted
```

Note that `stop_monitor all` also accepts a quoted `'*'`. Leave it unquoted and the shell will expand it first.

## Scope

`rfmon` is the control plane: interface state, not packet I/O.

- No frame capture or injection. Keeping that out keeps the crate small and its dependency tree short.
- No 80 or 160 MHz channel widths. 20 MHz carries management and EAPOL, avoids centre frequency edge cases, and wide capture is rarely what you want.

## Licence

MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
