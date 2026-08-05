//! NetworkManager coordination over D-Bus.
//!
//! Before an interface can be driven into monitor mode it must be released from
//! whatever is managing it; otherwise that service fights the mode change,
//! resets the device, or reconnects it out from under us. On a desktop or
//! server distro that manager is usually NetworkManager, which also owns its own
//! wpa_supplicant, so releasing here transitively releases the supplicant too.
//!
//! Every function is **durable**: if NetworkManager is not installed, not
//! running, or there is no system D-Bus at all, [`is_present`] reports `false`
//! and the caller falls back (see [`crate::linux::supplicant`]). Changing a
//! device's `Managed` property is privileged (polkit), so the mutating calls
//! require root or an authorizing policy.
//!
//! Durability covers one more case that [`is_present`] cannot: NetworkManager
//! *is* running, but does not track this particular interface. That is the
//! normal state for a monitor-mode vif, which NetworkManager ignores, and for
//! any device excluded via `unmanaged-devices`, which is how a dedicated capture
//! radio is usually set up. There is nothing to release or hand back in that
//! case, so it is a no-op rather than an error. Only `UnknownDevice` is treated
//! this way; a device NetworkManager knows about but refuses to change still
//! surfaces as a failure.

use tracing::debug;

use crate::Result;
use crate::errors::LinuxError;
use crate::linux::{DBUS_TIMEOUT, with_timeout};

/* Constants */

const NM_SERVICE: &str = "org.freedesktop.NetworkManager";

// The D-Bus error NetworkManager raises for an interface it does not track.
// Distinguished from every other failure because it means "nothing to do", not
// "the operation failed". See the module docs.
const NM_UNKNOWN_DEVICE: &str = "org.freedesktop.NetworkManager.UnknownDevice";

/* D-Bus proxies */

// NetworkManager's root object, used only to resolve an interface name to its
// device object path.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    fn get_device_by_ip_iface(&self, iface: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

// A single network device. `Managed` is the read/write property we toggle.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Device {
    #[zbus(property)]
    fn set_managed(&self, value: bool) -> zbus::Result<()>;
}

/* Free functions */

/// Whether NetworkManager is present and reachable on the system bus.
///
/// Returns `false`, never an error, if there is no system bus or the service
/// has no owner, so callers can branch on availability without special-casing
/// headless hosts.
pub(crate) async fn is_present() -> bool {
    // A wedged system bus must not hang the probe (this runs on the teardown
    // path, including inside a blocking Drop), so bound it and read any timeout
    // or error as "not present"; the caller then simply falls back.
    let probe = async {
        let connection = zbus::Connection::system().await.ok()?;
        let dbus = zbus::fdo::DBusProxy::new(&connection).await.ok()?;
        let name = NM_SERVICE.try_into().ok()?;
        dbus.name_has_owner(name).await.ok()
    };
    matches!(
        tokio::time::timeout(DBUS_TIMEOUT, probe).await,
        Ok(Some(true))
    )
}

/// Ask NetworkManager to stop managing `iface`.
///
/// Idempotent from the caller's perspective: setting `Managed = false` on an
/// already-unmanaged device is harmless. Requires that NetworkManager actually
/// be present (guard with [`is_present`]).
pub(crate) async fn release(iface: &str) -> Result<()> {
    with_timeout("NetworkManager release", DBUS_TIMEOUT, async {
        let Some(device) = device_proxy(iface).await? else {
            debug!(
                iface,
                "NetworkManager is not tracking interface; nothing to release"
            );
            return Ok(());
        };
        device
            .set_managed(false)
            .await
            .map_err(nm_error("set_unmanaged", iface))?;
        debug!(iface, "released interface from NetworkManager");
        Ok(())
    })
    .await
}

/// Hand `iface` back to NetworkManager to manage again.
pub(crate) async fn reclaim(iface: &str) -> Result<()> {
    with_timeout("NetworkManager reclaim", DBUS_TIMEOUT, async {
        let Some(device) = device_proxy(iface).await? else {
            debug!(
                iface,
                "NetworkManager is not tracking interface; nothing to hand back"
            );
            return Ok(());
        };
        device
            .set_managed(true)
            .await
            .map_err(nm_error("set_managed", iface))?;
        debug!(iface, "returned interface to NetworkManager");
        Ok(())
    })
    .await
}

// Resolve an interface name to a NetworkManager device proxy on the system bus.
//
// `Ok(None)` means NetworkManager is reachable but has no such device, which is
// a normal state rather than a failure. See the module docs. Every other
// failure, including a connection that cannot be established, is still an error:
// silently skipping a release that should have happened would leave
// NetworkManager free to pull the interface back out of monitor mode.
async fn device_proxy(iface: &str) -> Result<Option<DeviceProxy<'static>>> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|source| LinuxError::DbusConnect { source })?;

    let manager = NetworkManagerProxy::new(&connection)
        .await
        .map_err(nm_error("connect", iface))?;

    let path = match manager.get_device_by_ip_iface(iface).await {
        Ok(path) => path,
        Err(error) if is_unknown_device(&error) => return Ok(None),
        Err(error) => return Err(nm_error("get_device", iface)(error)),
    };

    let device = DeviceProxy::builder(&connection)
        .path(path)
        .map_err(nm_error("device_path", iface))?
        .build()
        .await
        .map_err(nm_error("device_proxy", iface))?;

    Ok(Some(device))
}

// Whether a D-Bus failure is NetworkManager reporting that it has no such
// device, as opposed to any other way the call can fail.
fn is_unknown_device(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _) if is_unknown_device_name(name.as_str()))
}

// Split out from `is_unknown_device` so the decision itself is testable without
// constructing a D-Bus reply message.
fn is_unknown_device_name(name: &str) -> bool {
    name == NM_UNKNOWN_DEVICE
}

// Build a mapper that tags a raw zbus error with the operation and interface.
fn nm_error(op: &'static str, iface: &str) -> impl Fn(zbus::Error) -> crate::Error {
    let iface = iface.to_string();
    move |source| {
        LinuxError::NetworkManager {
            op,
            iface: iface.clone(),
            source,
        }
        .into()
    }
}

/* Tests */
//
// The D-Bus calls themselves need a live system bus and a running
// NetworkManager, so they are exercised by `examples/full_cycle.rs` against real
// hardware. What is unit-testable here is the decision that governs whether a
// failure is swallowed at all.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unknown_device_means_not_tracked() {
        assert!(is_unknown_device_name(NM_UNKNOWN_DEVICE));

        // Everything else must keep propagating. Swallowing a permission
        // failure would skip a release that was needed and let NetworkManager
        // pull the interface back out of monitor mode mid-capture: the failure
        // this whole release/reclaim dance exists to prevent.
        for name in [
            "org.freedesktop.NetworkManager.PermissionDenied",
            "org.freedesktop.NetworkManager.Device.NotAllowed",
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "org.freedesktop.DBus.Error.AccessDenied",
            "",
        ] {
            assert!(
                !is_unknown_device_name(name),
                "`{name}` must not be treated as an untracked device",
            );
        }
    }

    #[test]
    fn unknown_device_name_is_the_documented_nm_error() {
        // Guards the constant against a typo: this exact name is what
        // NetworkManager raises from GetDeviceByIpIface, and a mismatch would
        // silently restore the hard-failure behaviour.
        assert_eq!(
            NM_UNKNOWN_DEVICE,
            "org.freedesktop.NetworkManager.UnknownDevice"
        );
    }
}
