//! wpa_supplicant coordination over D-Bus.
//!
//! On headless or minimal Linux hosts that do not run NetworkManager,
//! wpa_supplicant is usually what holds the wireless interface in managed mode.
//! It exposes a distro-agnostic D-Bus API (`fi.w1.wpa_supplicant1`) that lets us
//! remove the interface from its control before entering monitor mode and add
//! it back afterward, the same effect NetworkManager's `Managed` toggle has,
//! without depending on any particular init system or service name.
//!
//! wpa_supplicant is released and reclaimed whenever it is *present*, not only
//! when NetworkManager is absent: a standalone supplicant holding this interface
//! will pull the mode back to managed underneath us (the case airmon-ng warns
//! about), so it must be dropped even alongside NetworkManager. Where NM owns
//! the supplicant itself, both operations are idempotent: `release` is a no-op
//! when the supplicant does not know the interface, and `reclaim` is a no-op
//! when it already does, so coordinating with both is safe. Every function is
//! durable: a wpa_supplicant that is not running, or built without the D-Bus
//! interface, reports [`is_present`] `false` and the caller proceeds without it.

use std::collections::HashMap;

use tracing::debug;
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::Result;
use crate::errors::LinuxError;
use crate::linux::{DBUS_TIMEOUT, with_timeout};

/* Constants */

const WPA_SERVICE: &str = "fi.w1.wpa_supplicant1";

/* D-Bus proxies */

// wpa_supplicant's root object. `GetInterface` resolves a kernel interface name
// to the supplicant's per-interface object; `CreateInterface` / `RemoveInterface`
// add and drop an interface from its control.
#[zbus::proxy(
    interface = "fi.w1.wpa_supplicant1",
    default_service = "fi.w1.wpa_supplicant1",
    default_path = "/fi/w1/wpa_supplicant1"
)]
trait WpaSupplicant {
    fn get_interface(&self, ifname: &str) -> zbus::Result<OwnedObjectPath>;
    fn create_interface(&self, args: HashMap<&str, Value<'_>>) -> zbus::Result<OwnedObjectPath>;
    fn remove_interface(&self, path: &zbus::zvariant::ObjectPath<'_>) -> zbus::Result<()>;
}

/* Free functions */

/// Whether wpa_supplicant is present and reachable on the system bus.
///
/// Returns `false`, never an error, if there is no system bus or the service
/// has no owner.
pub(crate) async fn is_present() -> bool {
    // Bounded and failure-tolerant for the same reason as the NetworkManager
    // probe: a stuck system bus must not hang teardown or a blocking Drop.
    let probe = async {
        let connection = zbus::Connection::system().await.ok()?;
        let dbus = zbus::fdo::DBusProxy::new(&connection).await.ok()?;
        let name = WPA_SERVICE.try_into().ok()?;
        dbus.name_has_owner(name).await.ok()
    };
    matches!(
        tokio::time::timeout(DBUS_TIMEOUT, probe).await,
        Ok(Some(true))
    )
}

/// Remove `iface` from wpa_supplicant's control, if it holds it.
///
/// If the supplicant is not currently managing the interface, this is a no-op;
/// there is nothing to release.
pub(crate) async fn release(iface: &str) -> Result<()> {
    with_timeout("wpa_supplicant release", DBUS_TIMEOUT, async {
        let proxy = proxy().await?;

        // GetInterface errors when the supplicant does not know the interface;
        // that simply means there is nothing to release.
        let Ok(path) = proxy.get_interface(iface).await else {
            debug!(
                iface,
                "wpa_supplicant is not managing interface; nothing to release"
            );
            return Ok(());
        };

        proxy
            .remove_interface(&path)
            .await
            .map_err(supplicant_error("remove_interface", iface))?;
        debug!(iface, "removed interface from wpa_supplicant");
        Ok(())
    })
    .await
}

/// Return `iface` to wpa_supplicant's control.
///
/// Adds the interface back so the supplicant resumes managing it. If the
/// supplicant is already managing it, that is treated as success.
pub(crate) async fn reclaim(iface: &str) -> Result<()> {
    with_timeout("wpa_supplicant reclaim", DBUS_TIMEOUT, async {
        let proxy = proxy().await?;

        // Already managed again? Nothing to do. This is also what makes reclaim
        // safe to call alongside NetworkManager: if NM re-added the interface
        // after we set it managed, this is a no-op rather than a conflict.
        if proxy.get_interface(iface).await.is_ok() {
            debug!(iface, "wpa_supplicant already managing interface");
            return Ok(());
        }

        let mut args: HashMap<&str, Value<'_>> = HashMap::new();
        args.insert("Ifname", Value::from(iface));

        proxy
            .create_interface(args)
            .await
            .map_err(supplicant_error("create_interface", iface))?;
        debug!(iface, "returned interface to wpa_supplicant");
        Ok(())
    })
    .await
}

// Connect to the system bus and build the wpa_supplicant root proxy.
async fn proxy() -> Result<WpaSupplicantProxy<'static>> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|source| LinuxError::DbusConnect { source })?;

    let proxy = WpaSupplicantProxy::new(&connection)
        .await
        .map_err(supplicant_error("connect", ""))?;

    Ok(proxy)
}

// Build a mapper that tags a raw zbus error with the operation and interface.
fn supplicant_error(op: &'static str, iface: &str) -> impl Fn(zbus::Error) -> crate::Error {
    let iface = iface.to_string();
    move |source| {
        LinuxError::Supplicant {
            op,
            iface: iface.clone(),
            source,
        }
        .into()
    }
}
