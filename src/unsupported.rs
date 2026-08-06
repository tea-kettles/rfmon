//! Placeholder backend for targets with no monitor-mode implementation.
//!
//! This module exists purely for diagnostics. The `compile_error!` in
//! [`crate`] already fails the build on any target that is not Linux or
//! Windows; without a `Backend` to alias, that one clear message would arrive
//! buried under an `undeclared type `Backend`` error at every call site in
//! [`crate::monitor`]. Supplying a placeholder keeps the failure to the single
//! message that explains it.
//!
//! Nothing here is reachable: the crate cannot finish compiling on a target
//! that selects this backend, so the bodies are [`unreachable!`].

use crate::Result;
use crate::interface::{ChannelWidth, InterfaceInfo, Tuning};
use crate::monitor::MonitorBackend;

/* Types */

/// Stand-in [`MonitorBackend`] for unsupported targets. Never constructed.
#[derive(Debug)]
pub(crate) struct UnsupportedBackend;

/* Implementations */

impl MonitorBackend for UnsupportedBackend {
    async fn detect() -> Result<Vec<InterfaceInfo>> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn start_auto() -> Result<InterfaceInfo> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn start_on(_name: &str) -> Result<InterfaceInfo> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn start_as(_name: &str, _new_name: &str) -> Result<InterfaceInfo> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn rename(_current: &str, _new: &str) -> Result<()> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn set_channel(
        _iface: &InterfaceInfo,
        _freq_mhz: u32,
        _width: ChannelWidth,
    ) -> Result<()> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn read_tuning(_iface: &InterfaceInfo) -> Result<Tuning> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }

    async fn stop(_name: &str) -> Result<()> {
        unreachable!("rfmon has no backend for this target; see the compile_error in lib.rs")
    }
}
