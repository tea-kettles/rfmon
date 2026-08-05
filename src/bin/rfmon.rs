//! `rfmon`, a small CLI for driving a wireless interface in and out of monitor
//! mode, mirroring the library API. A scriptable, crash-recoverable alternative
//! to airmon-ng's start/stop.
//!
//! ```text
//! rfmon [-v] start_monitor [<iface>]          auto-select if no iface given
//! rfmon [-v] start_monitor_as <iface> <new>   enter monitor, then rename to <new>
//! rfmon [-v] stop_monitor <iface>             restore managed networking by name
//! rfmon [-v] stop_monitor all                 restore every monitor-mode interface
//! rfmon [-v] reset                            stop all monitors + restart services
//! rfmon [-v] list                             show interfaces and what they support
//! ```
//!
//! The `start_*` commands leave the interface in monitor mode after the process
//! exits (like airmon-ng), so pair them with `stop_monitor` to undo. Because
//! `stop_monitor` works purely by name, it also recovers an interface stranded
//! by a crashed program; `stop_monitor all` sweeps every monitor interface, and
//! `reset` is the worst-case hammer: sweep them all, then restart
//! wpa_supplicant and NetworkManager if present. Requires root (CAP_NET_ADMIN).
//! Logs at info level; `-v` adds debug.

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

// Services rfmon coordinates with; restarted (if present) by `reset`.
const SERVICES: &[&str] = &["wpa_supplicant", "NetworkManager"];

const USAGE: &str = "\
usage:
  rfmon [-v] start_monitor [<iface>]          enter monitor mode (auto-select if no iface)
  rfmon [-v] start_monitor_as <iface> <new>   enter monitor mode, then rename to <new>
  rfmon [-v] stop_monitor <iface>             restore managed networking by name
  rfmon [-v] stop_monitor all                 restore every monitor-mode interface
  rfmon [-v] reset                            stop all monitors + restart wpa_supplicant/NetworkManager
  rfmon [-v] list                             show interfaces, capabilities and channels

  -v, --verbose   debug-level logging
  note: `list` is read-only and does not need root; everything else does.

note: use `stop_monitor all` (or a quoted `'*'`); an unquoted * is expanded by the shell.";

/* Types */

// A CLI failure: either bad arguments (print usage) or a library error (already
// logged, just exit nonzero).
#[derive(Debug)]
enum CliError {
    Usage(String),
    Rfmon(rfmon::Error),
}

impl From<rfmon::Error> for CliError {
    fn from(error: rfmon::Error) -> Self {
        CliError::Rfmon(error)
    }
}

/* Entry point */

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = extract_flag(&mut args, "-v", "--verbose");
    init_tracing(verbose);

    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(message)) => {
            eprintln!("rfmon: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(CliError::Rfmon(error)) => {
            error!(%error, "command failed");
            ExitCode::FAILURE
        }
    }
}

/* Command dispatch */

async fn run(args: &[String]) -> Result<(), CliError> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("no command given".into()))?;

    match command.as_str() {
        "start_monitor" | "start" => match rest {
            [] => {
                let name = rfmon::start_monitor().await?.persist();
                info!(iface = %name, "monitor mode");
                Ok(())
            }
            [iface] => {
                let name = rfmon::start_monitor_on(iface).await?.persist();
                info!(iface = %name, "monitor mode");
                Ok(())
            }
            _ => Err(CliError::Usage(
                "start_monitor takes at most one interface".into(),
            )),
        },
        "start_monitor_as" => match rest {
            [iface, new_name] => {
                let name = rfmon::start_monitor_as(iface, new_name).await?.persist();
                info!(iface = %name, "monitor mode");
                Ok(())
            }
            _ => Err(CliError::Usage(
                "usage: rfmon start_monitor_as <iface> <new_name>".into(),
            )),
        },
        "stop_monitor" | "stop" => match rest {
            [target] if target == "*" || target == "all" => {
                stop_all().await?;
                Ok(())
            }
            [iface] => {
                let name = rfmon::stop_monitor(iface).await?;
                info!(iface = %name, "managed mode");
                Ok(())
            }
            _ => Err(CliError::Usage(
                "usage: rfmon stop_monitor <iface|all>".into(),
            )),
        },
        // Worst-case recovery: sweep every interface out of monitor mode, then
        // restart the network services so connectivity comes back.
        "reset" => match rest {
            [] => {
                stop_all().await?;
                for service in SERVICES {
                    restart_service(service);
                }
                Ok(())
            }
            _ => Err(CliError::Usage("reset takes no arguments".into())),
        },
        "list" | "ls" => match rest {
            [] => list().await,
            _ => Err(CliError::Usage("list takes no arguments".into())),
        },
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(CliError::Usage(format!("unknown command '{other}'"))),
    }
}

/* Helpers */

// Restore every monitor-mode interface, logging one line per interface (or a
// note if there were none).
async fn stop_all() -> Result<(), CliError> {
    let restored = rfmon::stop_all_monitors().await?;
    if restored.is_empty() {
        info!("no interfaces in monitor mode");
    } else {
        for name in restored {
            info!(iface = %name, "managed mode");
        }
    }
    Ok(())
}

// Print every wireless interface with what it can do.
//
// Written to stdout rather than through `tracing`: this is a report the operator
// asked for, not an event that happened, and it should not disappear because
// someone set `RUST_LOG`. The same reason `--help` uses `println!`.
//
// Read-only, and the only command that does not need root, since the nl80211 dumps
// behind `detect` are readable by any user.
async fn list() -> Result<(), CliError> {
    let interfaces = rfmon::WirelessInterface::detect().await?;
    if interfaces.is_empty() {
        println!("no wireless interfaces found");
        return Ok(());
    }

    for (position, iface) in interfaces.iter().enumerate() {
        if position > 0 {
            println!();
        }

        println!("{}  (score {})", iface.name(), iface.monitor_score());

        // An interface already in monitor mode is one rfmon refuses to take, so
        // say that here rather than leaving the operator to discover it from an
        // error later.
        if iface.is_monitor() {
            println!("  mode     monitor  (in use; rfmon will not take this interface)");
        } else {
            println!("  mode     {}", iface.mode());
        }

        println!(
            "  device   {} on {}",
            iface.driver().unwrap_or("unknown driver"),
            iface.bus(),
        );
        println!("  mac      {}", iface.mac());
        println!("  monitor  {}", monitor_support(iface));
        println!("  ssid     {}", iface.ssid().unwrap_or("-"));

        for band in iface.bands() {
            // Disabled channels are listed nowhere: the regulatory domain has
            // ruled them out, and `set_channel` rejects them, so showing them
            // would only suggest they are available.
            let usable: Vec<String> = band
                .frequencies()
                .iter()
                .filter(|freq| !freq.is_disabled())
                .map(|freq| match freq.channel() {
                    Some(channel) => channel.to_string(),
                    // A frequency off the known channel grid can still be
                    // reported; name it by frequency so it is not silently
                    // dropped from the count.
                    None => format!("{}MHz", freq.mhz()),
                })
                .collect();
            println!(
                "  {:<8} {} usable: {}",
                band.kind().to_string(),
                usable.len(),
                usable.join(","),
            );
        }
    }
    Ok(())
}

// How the library sees this interface's monitor capability, in the same three
// tiers selection uses.
fn monitor_support(iface: &rfmon::WirelessInterface) -> &'static str {
    if iface.supports_monitor() {
        "advertised over nl80211"
    } else if iface.is_monitor_plausible() {
        "not advertised, but this driver family supports it in practice"
    } else {
        "not supported"
    }
}

// Resolve `systemctl` to an absolute path.
//
// `reset` runs as root, so invoking `systemctl` by bare name would search
// `$PATH`, and `sudo` does not always sanitize `$PATH` (no `secure_path`, or
// `sudo -E`). A writable directory earlier in `$PATH` would then let an
// unprivileged user redirect this root process to a binary of their choosing.
// An absolute path is resolved by the kernel without any `$PATH` search, so a
// hostile `$PATH` cannot intercept it. `/usr/bin/systemctl` is canonical; the
// historical `/bin` path is a symlink to it on merged-`/usr` systems.
fn systemctl() -> &'static str {
    if Path::new("/usr/bin/systemctl").exists() {
        "/usr/bin/systemctl"
    } else {
        "/bin/systemctl"
    }
}

// Restart a systemd service if it exists on this host. Best-effort: a missing
// service or a non-systemd host is logged and skipped, never fatal.
fn restart_service(unit: &str) {
    // Ask systemctl whether the concrete unit exists and let its exit code
    // answer. A previous substring scan of `list-unit-files` matched template
    // units too: `wpa_supplicant@.service` satisfied a check for
    // `wpa_supplicant`, after which the restart of the (absent) plain unit
    // failed. `cat <unit>.service` exits non-zero when the exact unit is unknown.
    let present = Command::new(systemctl())
        .args(["cat", "--no-pager", &format!("{unit}.service")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if !present {
        info!(service = unit, "not present; skipping restart");
        return;
    }

    match Command::new(systemctl()).args(["restart", unit]).status() {
        Ok(status) if status.success() => info!(service = unit, "restarted"),
        Ok(status) => warn!(service = unit, code = status.code(), "restart failed"),
        Err(error) => warn!(service = unit, %error, "could not run systemctl"),
    }
}

// Remove a boolean flag from the argument list, returning whether it was present.
fn extract_flag(args: &mut Vec<String>, short: &str, long: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == short || a == long) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn init_tracing(verbose: bool) {
    let default = if verbose {
        "debug,rfmon=debug"
    } else {
        "info,rfmon=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| default.into()))
        .with_target(false)
        .init();
}

/* Tests */
//
// Argument handling only. The commands themselves are thin wrappers over the
// library calls, which are covered against a mock backend in `monitor.rs`, and
// `restart_service` shells out to systemd, so neither is meaningfully testable
// here without a live host.

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn extract_flag_removes_short_form() {
        let mut argv = args(&["-v", "start_monitor"]);
        assert!(extract_flag(&mut argv, "-v", "--verbose"));
        assert_eq!(argv, ["start_monitor"]);
    }

    #[test]
    fn extract_flag_removes_long_form() {
        let mut argv = args(&["stop_monitor", "--verbose", "wlan0"]);
        assert!(extract_flag(&mut argv, "-v", "--verbose"));
        // Only the flag is removed; the positional order is preserved, so the
        // command still parses as `stop_monitor wlan0`.
        assert_eq!(argv, ["stop_monitor", "wlan0"]);
    }

    #[test]
    fn extract_flag_absent_leaves_args_untouched() {
        let mut argv = args(&["start_monitor", "wlan0"]);
        assert!(!extract_flag(&mut argv, "-v", "--verbose"));
        assert_eq!(argv, ["start_monitor", "wlan0"]);
    }

    #[test]
    fn extract_flag_removes_first_only() {
        // Documents the behaviour rather than endorsing it: a second `-v` is
        // left in place and will be rejected as an unknown argument, which is a
        // clearer outcome than silently accepting a malformed command line.
        let mut argv = args(&["-v", "-v", "reset"]);
        assert!(extract_flag(&mut argv, "-v", "--verbose"));
        assert_eq!(argv, ["-v", "reset"]);
    }

    #[tokio::test]
    async fn no_command_is_a_usage_error() {
        let err = run(&[]).await.unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[tokio::test]
    async fn unknown_command_is_a_usage_error() {
        let err = run(&args(&["frobnicate"])).await.unwrap_err();
        match err {
            CliError::Usage(message) => assert!(message.contains("frobnicate")),
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn too_many_arguments_is_a_usage_error() {
        // Each arity guard is reachable without touching the library, because
        // the argument shape is rejected before any backend call.
        for argv in [
            args(&["start_monitor", "wlan0", "extra"]),
            args(&["start_monitor_as", "wlan0"]),
            args(&["stop_monitor", "wlan0", "extra"]),
            args(&["reset", "extra"]),
            args(&["list", "extra"]),
        ] {
            let err = run(&argv).await.unwrap_err();
            assert!(
                matches!(err, CliError::Usage(_)),
                "expected a usage error for {argv:?}",
            );
        }
    }

    #[tokio::test]
    async fn help_is_not_an_error() {
        for flag in ["-h", "--help", "help"] {
            assert!(run(&args(&[flag])).await.is_ok(), "{flag} should succeed");
        }
    }
}
