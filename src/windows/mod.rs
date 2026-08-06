//! Windows monitor-mode backend (stub).
//!
//! Native Windows offers no 802.11 monitor mode through the WLAN API, so a real
//! implementation must drive [Npcap](https://npcap.com) against a cooperating
//! adapter and driver. That work is not done yet: this backend satisfies the
//! [`MonitorBackend`](crate::monitor::MonitorBackend) contract so the crate
//! compiles and exposes an identical API on Windows, but every call fails with
//! [`WindowsError::Unsupported`](crate::errors::WindowsError::Unsupported).
//!
//! The submodules mark where the eventual implementation goes:
//!   * [`interface`]: adapter enumeration via the native WLAN API.
//!   * [`npcap`]: the Npcap-backed monitor toggle and capture handle.

pub(crate) mod interface;
pub(crate) mod npcap;

use crate::Result;
use crate::errors::WindowsError;
use crate::interface::InterfaceInfo;
use crate::monitor::MonitorBackend;

/* Types */

/// The Windows implementation of [`MonitorBackend`](crate::monitor::MonitorBackend).
///
/// Currently a stub; see the module docs.
#[derive(Debug)]
pub(crate) struct WindowsBackend;

/* Implementations */

impl MonitorBackend for WindowsBackend {
    async fn detect() -> Result<Vec<InterfaceInfo>> {
        Err(WindowsError::Unsupported.into())
    }

    async fn start_auto() -> Result<InterfaceInfo> {
        Err(WindowsError::Unsupported.into())
    }

    async fn start_on(_name: &str) -> Result<InterfaceInfo> {
        Err(WindowsError::Unsupported.into())
    }

    async fn start_as(_name: &str, _new_name: &str) -> Result<InterfaceInfo> {
        Err(WindowsError::Unsupported.into())
    }

    async fn rename(_current: &str, _new: &str) -> Result<()> {
        Err(WindowsError::Unsupported.into())
    }

    async fn set_channel(
        _iface: &InterfaceInfo,
        _freq_mhz: u32,
        _width: crate::interface::ChannelWidth,
    ) -> Result<()> {
        Err(WindowsError::Unsupported.into())
    }

    async fn read_tuning(_iface: &InterfaceInfo) -> Result<crate::interface::Tuning> {
        Err(WindowsError::Unsupported.into())
    }

    async fn stop(_name: &str) -> Result<()> {
        Err(WindowsError::Unsupported.into())
    }
}
