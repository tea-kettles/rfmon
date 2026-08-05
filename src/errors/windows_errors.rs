//! Errors raised by the Windows backend.
//!
//! The Windows backend is a stub: native 802.11 monitor mode is not exposed by
//! the Windows WLAN API, so a working implementation must go through Npcap with
//! a cooperating adapter/driver. Until that is built, every backend call fails
//! with [`WindowsError::Unsupported`].
//!
//! Currently leaving this open if something changes with Windows in the future

/* Types */

/// A failure originating in the Windows backend.
///
/// `#[non_exhaustive]` so the real Npcap-backed implementation can add its own
/// failure modes without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WindowsError {
    /// Monitor mode is not yet implemented on Windows.
    #[error("Windows monitor-mode support is not yet implemented (requires Npcap)")]
    Unsupported,
}
