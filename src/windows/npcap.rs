//! Npcap-backed monitor mode for Windows (stub).
//!
//! Placeholder for the real Windows monitor path: opening an adapter through
//! Npcap and requesting monitor (radio-monitor) mode via
//! `PacketSetMonitorMode` / the Npcap API, which only succeeds on adapters whose
//! driver cooperates. Not yet implemented. See [`crate::windows`].
//!
//! Currently leaving this open if something changes with Windows in the future
