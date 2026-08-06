//! RAII teardown for a renamed monitor session.
//!
//! [`start_monitor_as`](crate::start_monitor_as) renames the interface, and a
//! bare rename would otherwise persist. [`MonitorGuard`] ties that rename to a
//! scope: restoring it renames the interface back to its original name and hands
//! it to managed networking.
//!
//! The reliable teardown is the explicit async [`MonitorGuard::restore`]. Because
//! Rust has no async `Drop` and the restore work is async (netlink + D-Bus), the
//! `Drop` impl is a best-effort safety net: it runs the restore to completion on
//! a dedicated thread with its own runtime and blocks until it finishes, so it
//! works even if the caller's runtime is gone, but it blocks the dropping
//! thread, so prefer `restore().await`.
//!
//! [`MonitorGuard`]'s tests live in [`crate::monitor`] rather than at the foot
//! of this file. Every one of them asserts on the backend calls teardown makes,
//! so they need the mock `Backend` that `monitor`'s test module defines;
//! duplicating that harness here would test the mock twice and the guard no
//! better.

use tracing::warn;

use crate::Result;
use crate::interface::{BandScope, ChannelWidth, InterfaceInfo, Tuning};
use crate::monitor::SetChannel;

/* Types */

/// RAII guard that restores a monitor session on teardown.
///
/// Returned by all three `start_*` calls
/// ([`start_monitor`](crate::start_monitor),
/// [`start_monitor_on`](crate::start_monitor_on),
/// [`start_monitor_as`](crate::start_monitor_as)). Restoring returns the
/// interface to managed networking, and, for
/// [`start_monitor_as`](crate::start_monitor_as), which renamed it, renames it
/// back to its original name first. Call
/// [`restore`](Self::restore) for deterministic teardown; dropping the guard
/// without doing so triggers a blocking best-effort restore and logs a warning.
#[must_use = "dropping the guard restores on a blocking best-effort basis; prefer restore().await"]
pub struct MonitorGuard {
    original: String,
    current: String,
    // The interface as resolved when it entered monitor mode. Its device caps
    // (index, bands) do not change for the session, since a rename alters only the
    // name, so tuning reuses it instead of re-enumerating. See `set_channel`.
    iface: InterfaceInfo,
    armed: bool,
}

/* Implementations */

impl MonitorGuard {
    /// A same-name session: the interface keeps its own name.
    pub(crate) fn new(iface: InterfaceInfo) -> Self {
        let name = iface.name().to_string();
        Self {
            original: name.clone(),
            current: name,
            iface,
            armed: true,
        }
    }

    /// A renamed session: `iface` is already under its new name, and teardown
    /// restores `original`.
    pub(crate) fn from_rename(original: String, iface: InterfaceInfo) -> Self {
        let current = iface.name().to_string();
        Self {
            original,
            current,
            iface,
            armed: true,
        }
    }

    /// The interface's current name (the renamed one).
    ///
    /// This is the name to hand to `pcap`, `libpnet`, or an `AF_PACKET` socket.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().await?;
    /// println!("capture on {}", mon.name());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.current
    }

    /// The name the interface will be restored to on teardown.
    ///
    /// Differs from [`name`](Self::name) only for a session started with
    /// [`start_monitor_as`](crate::start_monitor_as), which renamed it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor_as("wlan0", "capture0").await?;
    /// assert_eq!(mon.name(), "capture0");
    /// assert_eq!(mon.original_name(), "wlan0");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn original_name(&self) -> &str {
        &self.original
    }

    /// The interface's static facts: MAC, bands, driver, bus, supported modes.
    ///
    /// The snapshot taken when this session entered monitor mode. Everything on
    /// it is a free field read, and everything on it is a property of the device
    /// rather than of the session, so none of it goes stale while the guard
    /// lives. For what *does* change during a session, see
    /// [`tuning`](Self::tuning).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().await?;
    /// println!("capturing on {} ({})", mon.name(), mon.info().mac());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn info(&self) -> &InterfaceInfo {
        &self.iface
    }

    /// Read back the channel this interface is currently sitting on.
    ///
    /// Live: this asks the OS every time rather than reporting anything cached,
    /// because the tuning is the one part of an interface's state a session
    /// changes as it runs, and because something outside this process can move
    /// it. One call answers frequency, channel number, and width together;
    /// [`channel`](Self::channel), [`frequency`](Self::frequency) and
    /// [`width`](Self::width) are conveniences over it that each cost their own
    /// read.
    ///
    /// **Prefer this when you want more than one of them.** The three values are
    /// correlated: which side a 40 MHz secondary sits on is defined by the
    /// segment centre *relative to the primary frequency*, so `width` has to
    /// read the frequency to answer at all. Asking separately means two reads,
    /// between which the interface can move, and the pair can then describe a
    /// state that never existed. One call cannot tear.
    ///
    /// # Errors
    ///
    /// A platform error if the readback fails. An interface that is simply not
    /// tuned is not an error: it reports a [`Tuning`] whose fields are all
    /// `None` (see [`Tuning::is_tuned`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().on_channel(36).await?;
    /// let tuning = mon.tuning().await?;
    /// assert_eq!(tuning.channel(), Some(36));
    /// println!("{:?} MHz at {:?}", tuning.frequency_mhz(), tuning.width());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn tuning(&self) -> Result<Tuning> {
        crate::monitor::read_tuning(&self.iface).await
    }

    /// The channel number this interface is currently on, read from the OS.
    ///
    /// `None` if the interface is not tuned, or sits on a frequency that is not
    /// on a recognised channel grid. Calls [`tuning`](Self::tuning); use that
    /// directly if you also want the width, to avoid a second readback.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().on_channel(11).await?;
    /// assert_eq!(mon.channel().await?, Some(11));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn channel(&self) -> Result<Option<u32>> {
        Ok(self.tuning().await?.channel())
    }

    /// The primary centre frequency in MHz this interface is currently on, read
    /// from the OS.
    ///
    /// The raw form of [`channel`](Self::channel), for when the channel number
    /// is not what you want: a device parked off the recognised channel grid
    /// reports `None` from `channel` but a real frequency here, and log or
    /// capture metadata often wants MHz regardless.
    ///
    /// Note this is the one readback with no counterpart on the way in. The
    /// library tunes by channel number ([`set_channel`](Self::set_channel)), so
    /// there is no `set_frequency` for it to mirror; the same is true of
    /// [`Tuning::width_mhz`] and [`Tuning::center_mhz`].
    ///
    /// `None` if the interface is not tuned. Calls [`tuning`](Self::tuning); use
    /// that directly if you also want the channel or width, to avoid a second
    /// readback.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().on_channel(36).await?;
    /// assert_eq!(mon.frequency().await?, Some(5180));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn frequency(&self) -> Result<Option<u32>> {
        Ok(self.tuning().await?.frequency_mhz())
    }

    /// The channel width this interface is currently using, read from the OS.
    ///
    /// `None` if the interface is not tuned or reports a width this library
    /// never requests (80 or 160 MHz, which something else would have had to
    /// set). Calls [`tuning`](Self::tuning); use that directly if you also want
    /// the channel, or if you need to see a width outside this set.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rfmon::ChannelWidth;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().on_channel(6).await?;
    /// assert_eq!(mon.width().await?, Some(ChannelWidth::Mhz20));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn width(&self) -> Result<Option<ChannelWidth>> {
        Ok(self.tuning().await?.width())
    }

    /// Tune the interface to a 2.4 or 5 GHz channel, reusing the interface this
    /// guard already resolved.
    ///
    /// The [`set_channel`](crate::set_channel) counterpart for a held guard: it
    /// skips the interface enumeration the free function must do, so a channel
    /// hop is a single verified `SET_WIPHY` rather than a re-scan of every radio
    /// on the system. Returns a builder: set width with
    /// [`with_width`](SetChannel::with_width), then `.await` it. 6 GHz is not
    /// searched here (see [`set_channel_6g`](Self::set_channel_6g)).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().await?;
    /// mon.set_channel(6).await?;   // cheap; no re-enumeration
    /// mon.set_channel(11).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_channel(&self, channel: u32) -> SetChannel {
        SetChannel::from_iface(self.iface.clone(), channel, BandScope::ExceptSixGhz)
    }

    /// Tune the interface to a 6 GHz channel, reusing the resolved interface.
    ///
    /// The 6 GHz counterpart to [`set_channel`](Self::set_channel); see
    /// [`crate::set_channel_6g`] for why 6 GHz is a separate call.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().await?;
    /// mon.set_channel_6g(37).await?;   // 6 GHz ch 37 = 6135 MHz
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_channel_6g(&self, channel: u32) -> SetChannel {
        SetChannel::from_iface(self.iface.clone(), channel, BandScope::SixGhzOnly)
    }

    /// Cancel automatic restoration and leave the interface as it is.
    ///
    /// Consumes the guard *without* restoring: the interface stays in monitor
    /// mode (and renamed, if applicable) after the guard is gone. This is for a
    /// fire-and-forget tool that deliberately leaves the card in monitor for
    /// another process. Pair it with [`stop_monitor`](crate::stop_monitor) to
    /// undo later. Returns the interface's current name.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// // What the CLI's `rfmon start_monitor` does: leave the card in monitor
    /// // mode after this process exits.
    /// let name = rfmon::start_monitor().await?.persist();
    /// println!("{name} left in monitor mode; run `rfmon stop_monitor {name}` to undo");
    /// # Ok(())
    /// # }
    /// ```
    pub fn persist(mut self) -> String {
        self.armed = false;
        std::mem::take(&mut self.current)
    }

    /// Rename the interface back to its original name and restore managed
    /// networking, consuming the guard.
    ///
    /// This is the correct teardown path. After it returns the guard is spent
    /// and its `Drop` does nothing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> rfmon::Result<()> {
    /// let mon = rfmon::start_monitor().await?;
    /// // ... capture on mon.name() ...
    /// let restored = mon.restore().await?;
    /// println!("{restored} is back on managed networking");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn restore(mut self) -> Result<String> {
        self.armed = false;
        crate::monitor::restore_named(&self.current, &self.original).await
    }
}

// Written out rather than derived: `InterfaceInfo` is `Debug`, but deriving
// would print the device's full band and frequency list, dozens of entries,
// every time a guard is formatted. What identifies a session is the pair of
// names and whether teardown is still armed.
impl std::fmt::Debug for MonitorGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorGuard")
            .field("current", &self.current)
            .field("original", &self.original)
            .field("armed", &self.armed)
            .finish()
    }
}

impl Drop for MonitorGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let current = self.current.clone();
        let original = self.original.clone();
        warn!(
            current = %current,
            original = %original,
            "MonitorGuard dropped without restore().await; running blocking best-effort restore \
             (prefer restore().await)"
        );

        // Run the async restore to completion on a dedicated thread with its own
        // runtime. This works regardless of the caller's runtime state: the
        // current thread may itself be a runtime worker, or the runtime may be
        // shutting down. The cost is blocking until teardown finishes.
        let joined = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    warn!(%error, "could not build a runtime for drop-time restore");
                    return;
                }
            };
            if let Err(error) = runtime.block_on(crate::monitor::restore_named(&current, &original))
            {
                warn!(%error, "best-effort restore on drop failed; interface may remain renamed");
            }
        })
        .join();

        if joined.is_err() {
            warn!("drop-time restore thread panicked");
        }
    }
}
