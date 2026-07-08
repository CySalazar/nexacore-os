//! Network commands: `ifconfig`.
//!
//! Unlike the other command modules, `ifconfig` needs live data from the
//! network stack — it goes through [`crate::netquery::NetQuery`] (injected
//! via [`crate::executor::ExecContext::net`]) rather than reading anything
//! from `env`/`fs`. Output formatting is delegated entirely to
//! `nexacore_cmd_ifconfig`, which owns the classic `ifconfig`-style layout.

use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use nexacore_cmd_ifconfig::{IfconfigCommand, format_all_interfaces, format_interface, parse_args};

use crate::executor::{BuiltinFn, ExecContext};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Register all network commands into `map`.
///
/// # Examples
///
/// ```rust
/// use std::collections::BTreeMap;
///
/// use nexacore_shell::{commands::net_cmds, executor::BuiltinFn};
///
/// let mut map: BTreeMap<String, BuiltinFn> = BTreeMap::new();
/// net_cmds::register(&mut map);
/// assert!(map.contains_key("ifconfig"));
/// ```
pub fn register(map: &mut BTreeMap<String, BuiltinFn>) {
    map.insert("ifconfig".into(), cmd_ifconfig as BuiltinFn);
}

// ── ifconfig ──────────────────────────────────────────────────────────────────

/// List or show network interfaces.
///
/// # Arguments
///
/// - *(none)* — list every known interface.
/// - `<iface>` — show a single interface's configuration.
///
/// `SetAddress`/`BringUp`/`BringDown` parse successfully but are not yet
/// supported by the M0 network-configuration service — the interface's real
/// state is driven by DHCP / link bring-up, not by admin override yet — so
/// they print a "not supported" message and return exit code `1`.
///
/// # Examples
///
/// ```rust
/// use nexacore_cmd_ifconfig::InterfaceDisplay;
/// use nexacore_shell::{env::ShellEnv, executor::ExecContext, glob::FsQuery, netquery::NetQuery};
///
/// struct NoFs;
/// impl FsQuery for NoFs {
///     fn list_dir(&self, _: &str) -> Result<Vec<String>, String> {
///         Ok(vec![])
///     }
/// }
///
/// struct OneIface;
/// impl NetQuery for OneIface {
///     fn list_interfaces(&self) -> Result<Vec<InterfaceDisplay>, String> {
///         Ok(vec![InterfaceDisplay {
///             name: "eth0".into(),
///             mac: nexacore_types::net::MacAddress([0; 6]),
///             ip: Some(nexacore_types::net::Ipv4Addr([192, 168, 1, 10])),
///             netmask: Some(nexacore_types::net::Ipv4Addr([255, 255, 255, 0])),
///             link_up: true,
///             rx_bytes: 100,
///             tx_bytes: 200,
///         }])
///     }
///     fn get_interface(&self, name: &str) -> Result<InterfaceDisplay, String> {
///         Err(format!("{name}: not found"))
///     }
/// }
///
/// let mut env = ShellEnv::new();
/// let fs = NoFs;
/// let net = OneIface;
/// let mut ctx = ExecContext {
///     env: &mut env,
///     last_exit_code: 0,
///     cwd: "/".into(),
///     fs: &fs,
///     net: &net,
///     output: Vec::new(),
///     audit_log: nexacore_shell::audit::AuditLog::new(),
/// };
/// let code = nexacore_shell::commands::net_cmds::cmd_ifconfig_pub(&["ifconfig".into()], &mut ctx);
/// assert_eq!(code, 0);
/// let out = String::from_utf8(ctx.output).unwrap();
/// assert!(out.contains("eth0"));
/// ```
pub fn cmd_ifconfig_pub(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    cmd_ifconfig(args, ctx)
}

fn cmd_ifconfig(args: &[String], ctx: &mut ExecContext<'_>) -> i32 {
    let str_args: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match parse_args(&str_args) {
        Ok(IfconfigCommand::ListAll) => match ctx.net.list_interfaces() {
            Ok(ifaces) if ifaces.is_empty() => {
                ctx.output.extend_from_slice(
                    b"ifconfig: no network interfaces (network still initializing?)\n",
                );
                0
            }
            Ok(ifaces) => {
                ctx.output
                    .extend_from_slice(format_all_interfaces(&ifaces).as_bytes());
                ctx.output.push(b'\n');
                0
            }
            Err(e) => {
                ctx.output
                    .extend_from_slice(format!("ifconfig: {e}\n").as_bytes());
                1
            }
        },
        Ok(IfconfigCommand::ShowInterface { name }) => match ctx.net.get_interface(&name) {
            Ok(iface) => {
                ctx.output
                    .extend_from_slice(format_interface(&iface).as_bytes());
                ctx.output.push(b'\n');
                0
            }
            Err(e) => {
                ctx.output
                    .extend_from_slice(format!("ifconfig: {name}: {e}\n").as_bytes());
                1
            }
        },
        // SetAddress/BringUp/BringDown: not supported until the network
        // service grows write-capable configuration (M0 scope, see the
        // module doc).
        Ok(
            IfconfigCommand::SetAddress { .. }
            | IfconfigCommand::BringUp { .. }
            | IfconfigCommand::BringDown { .. },
        ) => {
            ctx.output
                .extend_from_slice(b"ifconfig: operation not supported\n");
            1
        }
        Err(_) => {
            ctx.output.extend_from_slice(b"ifconfig: usage error\n");
            1
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use nexacore_cmd_ifconfig::InterfaceDisplay;
    use nexacore_types::net::{Ipv4Addr, MacAddress};

    use super::*;
    use crate::{audit::AuditLog, env::ShellEnv, glob::FsQuery, netquery::NoNet};

    struct NoFs;
    impl FsQuery for NoFs {
        fn list_dir(&self, _path: &str) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }

    struct OneIface;
    impl NetQuery for OneIface {
        fn list_interfaces(&self) -> Result<Vec<InterfaceDisplay>, String> {
            Ok(alloc::vec![InterfaceDisplay {
                name: "eth0".to_string(),
                mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
                ip: Some(Ipv4Addr([192, 168, 1, 10])),
                netmask: Some(Ipv4Addr([255, 255, 255, 0])),
                link_up: true,
                rx_bytes: 42,
                tx_bytes: 7,
            }])
        }

        fn get_interface(&self, name: &str) -> Result<InterfaceDisplay, String> {
            if name == "eth0" {
                self.list_interfaces()
                    .map(|v| v.into_iter().next().expect("one interface"))
            } else {
                Err(format!("{name}: not found"))
            }
        }
    }

    use crate::netquery::NetQuery;

    fn ctx_with<'a>(
        env: &'a mut ShellEnv,
        fs: &'a dyn FsQuery,
        net: &'a dyn NetQuery,
    ) -> ExecContext<'a> {
        ExecContext {
            env,
            last_exit_code: 0,
            cwd: "/".into(),
            fs,
            net,
            output: Vec::new(),
            audit_log: AuditLog::new(),
        }
    }

    #[test]
    fn ifconfig_registers() {
        let mut map = BTreeMap::new();
        register(&mut map);
        assert!(map.contains_key("ifconfig"));
    }

    #[test]
    fn ifconfig_no_args_lists_interfaces() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let net = OneIface;
        let mut ctx = ctx_with(&mut env, &fs, &net);
        let code = cmd_ifconfig(&["ifconfig".to_string()], &mut ctx);
        assert_eq!(code, 0);
        let out = String::from_utf8(ctx.output).unwrap();
        assert!(out.contains("eth0"), "got: {out}");
        assert!(out.contains("192.168.1.10"), "got: {out}");
    }

    #[test]
    fn ifconfig_empty_list_reports_initializing() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let net = NoNet;
        let mut ctx = ctx_with(&mut env, &fs, &net);
        let code = cmd_ifconfig(&["ifconfig".to_string()], &mut ctx);
        assert_eq!(code, 0);
        let out = String::from_utf8(ctx.output).unwrap();
        assert!(out.contains("initializing"), "got: {out}");
    }

    #[test]
    fn ifconfig_named_interface_shows_it() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let net = OneIface;
        let mut ctx = ctx_with(&mut env, &fs, &net);
        let code = cmd_ifconfig(&["ifconfig".to_string(), "eth0".to_string()], &mut ctx);
        assert_eq!(code, 0);
        let out = String::from_utf8(ctx.output).unwrap();
        assert!(out.contains("eth0:"), "got: {out}");
    }

    #[test]
    fn ifconfig_unknown_interface_errors() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let net = OneIface;
        let mut ctx = ctx_with(&mut env, &fs, &net);
        let code = cmd_ifconfig(&["ifconfig".to_string(), "eth9".to_string()], &mut ctx);
        assert_eq!(code, 1);
        let out = String::from_utf8(ctx.output).unwrap();
        assert!(out.contains("eth9"), "got: {out}");
    }

    #[test]
    fn ifconfig_set_address_not_supported() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let net = OneIface;
        let mut ctx = ctx_with(&mut env, &fs, &net);
        let code = cmd_ifconfig(
            &[
                "ifconfig".to_string(),
                "eth0".to_string(),
                "10.0.0.1".to_string(),
                "255.0.0.0".to_string(),
            ],
            &mut ctx,
        );
        assert_eq!(code, 1);
        let out = String::from_utf8(ctx.output).unwrap();
        assert!(out.contains("not supported"), "got: {out}");
    }

    #[test]
    fn ifconfig_usage_error_on_too_many_args() {
        let mut env = ShellEnv::new();
        let fs = NoFs;
        let net = OneIface;
        let mut ctx = ctx_with(&mut env, &fs, &net);
        let code = cmd_ifconfig(
            &[
                "ifconfig".to_string(),
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            &mut ctx,
        );
        assert_eq!(code, 1);
        let out = String::from_utf8(ctx.output).unwrap();
        assert!(out.contains("usage error"), "got: {out}");
    }
}
