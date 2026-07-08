//! Capability-gated system bindings (WS18-03.6–.10).
//!
//! The pure stdlib modules (`string`/`math`/`json`/…) are computation. *System
//! bindings* are the effectful half: reading a file, opening a socket, invoking
//! a model, reading the config store, talking to another process. Each is
//! reachable from a script only as a `namespace::function(..)` call, only when
//! the caller granted the matching capability, and only through a host-provided
//! backend — there is no ambient access.
//!
//! [`SystemBindings`] is a single [`EffectHandler`] that wires all five binding
//! families to their capabilities and forwards the call to an injected backend:
//!
//! | Namespace | Functions | Capability | Backend | Sub-task |
//! |-----------|-----------|------------|---------|----------|
//! | `fs`      | `read`, `exists` / `write` | `fs.read` / `fs.write` | [`FsBackend`] | .6 |
//! | `net`     | `connect` | `net.connect` | [`NetBackend`] | .7 |
//! | `ai`      | `invoke`, `embed`, `classify` | `ai.invoke` / `ai.embed` / `ai.classify` | [`AiBackend`] | .8 |
//! | `config`  | `get`, `set` | `config.read` / `config.write` | [`ConfigBackend`] | .9 |
//! | `proc`/`ipc` | `spawn` / `send`, `recv` | `proc.spawn` / `ipc.send` / `ipc.recv` | [`IpcBackend`] | .10 |
//!
//! The reserved namespaces always resolve to an effect (a required capability),
//! even when no backend is wired: an ungranted call is denied by the
//! interpreter's gate, and a granted call with no backend is a clean runtime
//! error — never a silent enum constructor. The capability *scope* is the first
//! string argument (a path for `fs`, a host for `net`, a key for `config`), so
//! grants can be narrowed to `fs.read` under `/etc/nexacore`, and so on.
//!
//! `no_std + alloc`, zero dependencies — backends are trait objects the host
//! supplies (a VFS handle for `fs`, the firewall-gated socket layer for `net`,
//! the inference runtime for `ai`, the config store for `config`, the IPC layer
//! for `proc`/`ipc`).

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
};

use crate::interp::{EffectHandler, HostValue, RuntimeError, Value};

/// Filesystem backend, reached via the capability-gated VFS (WS3-02).
pub trait FsBackend {
    /// Read `path` to a string.
    ///
    /// # Errors
    /// A message if the path is absent or unreadable.
    fn read(&mut self, path: &str) -> Result<String, String>;

    /// Write `data` to `path`.
    ///
    /// # Errors
    /// A message if the write fails.
    fn write(&mut self, path: &str, data: &str) -> Result<(), String>;

    /// Whether `path` exists.
    fn exists(&mut self, path: &str) -> bool;
}

/// Network backend, reached behind the firewall network capability (WS4-05).
pub trait NetBackend {
    /// Open a connection to `host`:`port`, returning an opaque socket handle.
    ///
    /// # Errors
    /// A message if the connection is refused or filtered.
    fn connect(&mut self, host: &str, port: i64) -> Result<i64, String>;
}

/// AI backend for the `ai_invoke` / `ai_embed` / `ai_classify` syscalls (WS5-03).
pub trait AiBackend {
    /// Invoke a model with `prompt`, returning the completion.
    ///
    /// # Errors
    /// A message if inference fails.
    fn invoke(&mut self, prompt: &str) -> Result<String, String>;

    /// Embed `text`, returning an encoded vector representation.
    ///
    /// # Errors
    /// A message if embedding fails.
    fn embed(&mut self, text: &str) -> Result<String, String>;

    /// Classify `text`, returning a label.
    ///
    /// # Errors
    /// A message if classification fails.
    fn classify(&mut self, text: &str) -> Result<String, String>;
}

/// Config-store backend, reached via the capability-gated store (WS17-01).
pub trait ConfigBackend {
    /// Read `key`, or `None` if it is unset.
    fn get(&mut self, key: &str) -> Option<String>;

    /// Set `key` to `value`.
    ///
    /// # Errors
    /// A message if the write fails.
    fn set(&mut self, key: &str, value: &str) -> Result<(), String>;
}

/// Process / IPC backend for the capability-gated process bindings.
pub trait IpcBackend {
    /// Spawn `command`, returning an opaque process handle.
    ///
    /// # Errors
    /// A message if the spawn fails.
    fn spawn(&mut self, command: &str) -> Result<i64, String>;

    /// Send `message` on `channel`.
    ///
    /// # Errors
    /// A message if delivery fails.
    fn send(&mut self, channel: &str, message: &str) -> Result<(), String>;

    /// Receive one message from `channel`.
    ///
    /// # Errors
    /// A message if the channel is closed or empty.
    fn recv(&mut self, channel: &str) -> Result<String, String>;
}

/// The composite capability-gated system-binding handler.
///
/// Construct it with [`SystemBindings::new`] and attach only the backends the
/// script is allowed to use; unattached families still resolve as effects (so
/// they are gated), but calling one yields a clean "backend not configured"
/// error rather than acting as inert data.
#[derive(Default)]
pub struct SystemBindings {
    fs: Option<Box<dyn FsBackend>>,
    net: Option<Box<dyn NetBackend>>,
    ai: Option<Box<dyn AiBackend>>,
    config: Option<Box<dyn ConfigBackend>>,
    ipc: Option<Box<dyn IpcBackend>>,
}

impl SystemBindings {
    /// A handler with no backends wired.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the filesystem backend (`fs` namespace).
    #[must_use]
    pub fn with_fs(mut self, backend: Box<dyn FsBackend>) -> Self {
        self.fs = Some(backend);
        self
    }

    /// Attach the network backend (`net` namespace).
    #[must_use]
    pub fn with_net(mut self, backend: Box<dyn NetBackend>) -> Self {
        self.net = Some(backend);
        self
    }

    /// Attach the AI backend (`ai` namespace).
    #[must_use]
    pub fn with_ai(mut self, backend: Box<dyn AiBackend>) -> Self {
        self.ai = Some(backend);
        self
    }

    /// Attach the config-store backend (`config` namespace).
    #[must_use]
    pub fn with_config(mut self, backend: Box<dyn ConfigBackend>) -> Self {
        self.config = Some(backend);
        self
    }

    /// Attach the process/IPC backend (`proc`/`ipc` namespaces).
    #[must_use]
    pub fn with_ipc(mut self, backend: Box<dyn IpcBackend>) -> Self {
        self.ipc = Some(backend);
        self
    }
}

/// Map a `namespace::function` to its required capability, or `None` if this
/// handler does not provide it. Kept free-standing so the mapping is a single
/// audit point.
fn capability_for(namespace: &str, function: &str) -> Option<&'static str> {
    Some(match (namespace, function) {
        ("fs", "read" | "exists") => "fs.read",
        ("fs", "write") => "fs.write",
        ("net", "connect") => "net.connect",
        ("ai", "invoke") => "ai.invoke",
        ("ai", "embed") => "ai.embed",
        ("ai", "classify") => "ai.classify",
        ("config", "get") => "config.read",
        ("config", "set") => "config.write",
        ("proc", "spawn") => "proc.spawn",
        ("ipc", "send") => "ipc.send",
        ("ipc", "recv") => "ipc.recv",
        _ => return None,
    })
}

fn str_arg<'a>(args: &'a [Value], i: usize, ctx: &str) -> Result<&'a str, RuntimeError> {
    match args.get(i) {
        Some(Value::Str(s, _)) => Ok(s.as_str()),
        _ => Err(RuntimeError::Msg(format!(
            "{ctx}: expected a string as argument {i}"
        ))),
    }
}

fn int_arg(args: &[Value], i: usize, ctx: &str) -> Result<i64, RuntimeError> {
    match args.get(i) {
        Some(Value::Int(n)) => Ok(*n),
        _ => Err(RuntimeError::Msg(format!(
            "{ctx}: expected an integer as argument {i}"
        ))),
    }
}

impl EffectHandler for SystemBindings {
    fn required_capability(&self, namespace: &str, function: &str) -> Option<String> {
        capability_for(namespace, function).map(ToString::to_string)
    }

    fn perform(
        &mut self,
        namespace: &str,
        function: &str,
        args: &[Value],
    ) -> Result<HostValue, RuntimeError> {
        let ctx = format!("{namespace}::{function}");
        match (namespace, function) {
            ("fs", "read") => {
                let path = str_arg(args, 0, &ctx)?;
                let fs = self.fs.as_mut().ok_or_else(|| no_backend("fs"))?;
                fs.read(path).map(HostValue::Str).map_err(RuntimeError::Msg)
            }
            ("fs", "write") => {
                let path = str_arg(args, 0, &ctx)?;
                let data = str_arg(args, 1, &ctx)?;
                let fs = self.fs.as_mut().ok_or_else(|| no_backend("fs"))?;
                fs.write(path, data)
                    .map(|()| HostValue::Unit)
                    .map_err(RuntimeError::Msg)
            }
            ("fs", "exists") => {
                let path = str_arg(args, 0, &ctx)?;
                let fs = self.fs.as_mut().ok_or_else(|| no_backend("fs"))?;
                Ok(HostValue::Bool(fs.exists(path)))
            }
            ("net", "connect") => {
                let host = str_arg(args, 0, &ctx)?;
                let port = int_arg(args, 1, &ctx)?;
                let net = self.net.as_mut().ok_or_else(|| no_backend("net"))?;
                net.connect(host, port)
                    .map(HostValue::Int)
                    .map_err(RuntimeError::Msg)
            }
            ("ai", "invoke" | "embed" | "classify") => {
                let text = str_arg(args, 0, &ctx)?;
                let ai = self.ai.as_mut().ok_or_else(|| no_backend("ai"))?;
                let out = match function {
                    "invoke" => ai.invoke(text),
                    "embed" => ai.embed(text),
                    _ => ai.classify(text),
                };
                out.map(HostValue::Str).map_err(RuntimeError::Msg)
            }
            ("config", "get") => {
                let key = str_arg(args, 0, &ctx)?;
                let config = self.config.as_mut().ok_or_else(|| no_backend("config"))?;
                // The HostValue vocabulary has no Option: a missing key maps to
                // Unit, a present key to its string value.
                Ok(config.get(key).map_or(HostValue::Unit, HostValue::Str))
            }
            ("config", "set") => {
                let key = str_arg(args, 0, &ctx)?;
                let value = str_arg(args, 1, &ctx)?;
                let config = self.config.as_mut().ok_or_else(|| no_backend("config"))?;
                config
                    .set(key, value)
                    .map(|()| HostValue::Unit)
                    .map_err(RuntimeError::Msg)
            }
            ("proc", "spawn") => {
                let command = str_arg(args, 0, &ctx)?;
                let ipc = self.ipc.as_mut().ok_or_else(|| no_backend("ipc"))?;
                ipc.spawn(command)
                    .map(HostValue::Int)
                    .map_err(RuntimeError::Msg)
            }
            ("ipc", "send") => {
                let channel = str_arg(args, 0, &ctx)?;
                let message = str_arg(args, 1, &ctx)?;
                let ipc = self.ipc.as_mut().ok_or_else(|| no_backend("ipc"))?;
                ipc.send(channel, message)
                    .map(|()| HostValue::Unit)
                    .map_err(RuntimeError::Msg)
            }
            ("ipc", "recv") => {
                let channel = str_arg(args, 0, &ctx)?;
                let ipc = self.ipc.as_mut().ok_or_else(|| no_backend("ipc"))?;
                ipc.recv(channel)
                    .map(HostValue::Str)
                    .map_err(RuntimeError::Msg)
            }
            _ => Err(RuntimeError::NoMethod(ctx)),
        }
    }
}

fn no_backend(family: &str) -> RuntimeError {
    RuntimeError::Msg(format!("no {family} backend configured"))
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;
    use crate::{
        interp::{Capability, Grants, Interpreter},
        parser::parse,
    };

    // ---- mock backends ------------------------------------------------------

    #[derive(Default)]
    struct MemFs {
        files: BTreeMap<String, String>,
    }
    impl FsBackend for MemFs {
        fn read(&mut self, path: &str) -> Result<String, String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| format!("no such file: {path}"))
        }
        fn write(&mut self, path: &str, data: &str) -> Result<(), String> {
            self.files.insert(path.to_string(), data.to_string());
            Ok(())
        }
        fn exists(&mut self, path: &str) -> bool {
            self.files.contains_key(path)
        }
    }

    struct StubAi;
    impl AiBackend for StubAi {
        fn invoke(&mut self, prompt: &str) -> Result<String, String> {
            Ok(format!("completion:{prompt}"))
        }
        fn embed(&mut self, _text: &str) -> Result<String, String> {
            Ok("[0.1,0.2]".to_string())
        }
        fn classify(&mut self, text: &str) -> Result<String, String> {
            Ok(if text.contains("buy now") {
                "spam"
            } else {
                "ham"
            }
            .to_string())
        }
    }

    struct StubNet;
    impl NetBackend for StubNet {
        fn connect(&mut self, _host: &str, port: i64) -> Result<i64, String> {
            Ok(port) // return the port as a stand-in handle
        }
    }

    #[derive(Default)]
    struct MemConfig {
        kv: BTreeMap<String, String>,
    }
    impl ConfigBackend for MemConfig {
        fn get(&mut self, key: &str) -> Option<String> {
            self.kv.get(key).cloned()
        }
        fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
            self.kv.insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    struct StubIpc;
    impl IpcBackend for StubIpc {
        fn spawn(&mut self, _command: &str) -> Result<i64, String> {
            Ok(4242)
        }
        fn send(&mut self, _channel: &str, _message: &str) -> Result<(), String> {
            Ok(())
        }
        fn recv(&mut self, channel: &str) -> Result<String, String> {
            Ok(format!("msg-from:{channel}"))
        }
    }

    fn run(src: &str, bindings: SystemBindings, grants: Grants) -> Result<Value, RuntimeError> {
        let program = parse(src).unwrap();
        let mut interp = Interpreter::new()
            .with_effect_handler(Box::new(bindings))
            .with_capabilities(grants);
        interp.load(&program);
        interp.run_main()
    }

    // ---- capability mapping (all five families, .6–.10) ---------------------

    #[test]
    fn capability_mapping_is_complete() {
        let b = SystemBindings::new();
        assert_eq!(
            b.required_capability("fs", "read").as_deref(),
            Some("fs.read")
        );
        assert_eq!(
            b.required_capability("fs", "exists").as_deref(),
            Some("fs.read")
        );
        assert_eq!(
            b.required_capability("fs", "write").as_deref(),
            Some("fs.write")
        );
        assert_eq!(
            b.required_capability("net", "connect").as_deref(),
            Some("net.connect")
        );
        assert_eq!(
            b.required_capability("ai", "classify").as_deref(),
            Some("ai.classify")
        );
        assert_eq!(
            b.required_capability("config", "get").as_deref(),
            Some("config.read")
        );
        assert_eq!(
            b.required_capability("config", "set").as_deref(),
            Some("config.write")
        );
        assert_eq!(
            b.required_capability("proc", "spawn").as_deref(),
            Some("proc.spawn")
        );
        assert_eq!(
            b.required_capability("ipc", "recv").as_deref(),
            Some("ipc.recv")
        );
        // Unknown namespaces are not effects.
        assert!(b.required_capability("string", "len").is_none());
        assert!(b.required_capability("fs", "chmod").is_none());
    }

    // ---- WS18-03.6 FS -------------------------------------------------------

    #[test]
    fn fs_read_gated_by_capability() {
        let mut fs = MemFs::default();
        fs.files
            .insert("/etc/nexacore/a.txt".to_string(), "hello".to_string());
        let bindings = SystemBindings::new().with_fs(Box::new(fs));
        let grant = Grants::none().with(Capability::scoped("fs.read", "/etc/nexacore"));
        let v = run(
            r#"fn main() { fs::read("/etc/nexacore/a.txt") }"#,
            bindings,
            grant,
        )
        .unwrap();
        assert_eq!(v.display(), "hello");
    }

    #[test]
    fn fs_read_denied_without_capability() {
        let fs = MemFs::default();
        let bindings = SystemBindings::new().with_fs(Box::new(fs));
        let e = run(
            r#"fn main() { fs::read("/etc/passwd") }"#,
            bindings,
            Grants::none(),
        )
        .unwrap_err();
        assert!(matches!(e, RuntimeError::CapabilityDenied(ref c) if c == "fs.read"));
    }

    #[test]
    fn fs_write_requires_write_capability_not_read() {
        // Holding only fs.read must not authorise fs::write.
        let bindings = SystemBindings::new().with_fs(Box::new(MemFs::default()));
        let e = run(
            r#"fn main() { fs::write("/etc/nexacore/x", "data") }"#,
            bindings,
            Grants::none().with(Capability::any("fs.read")),
        )
        .unwrap_err();
        assert!(matches!(e, RuntimeError::CapabilityDenied(ref c) if c == "fs.write"));
    }

    // ---- WS18-03.7 net ------------------------------------------------------

    #[test]
    fn net_connect_gated_and_returns_handle() {
        let bindings = SystemBindings::new().with_net(Box::new(StubNet));
        let grant = Grants::none().with(Capability::any("net.connect"));
        let v = run(
            r#"fn main() { net::connect("api.example.com", 443) }"#,
            bindings,
            grant,
        )
        .unwrap();
        assert!(matches!(v, Value::Int(443)));
    }

    // ---- WS18-03.8 AI -------------------------------------------------------

    #[test]
    fn ai_classify_gated_by_capability() {
        let bindings = SystemBindings::new().with_ai(Box::new(StubAi));
        let grant = Grants::none().with(Capability::any("ai.classify"));
        let v = run(
            r#"fn main() { ai::classify("buy now cheap") }"#,
            bindings,
            grant,
        )
        .unwrap();
        assert_eq!(v.display(), "spam");
    }

    #[test]
    fn ai_denied_without_capability() {
        let bindings = SystemBindings::new().with_ai(Box::new(StubAi));
        let e = run(
            r#"fn main() { ai::invoke("hello") }"#,
            bindings,
            Grants::none(),
        )
        .unwrap_err();
        assert!(matches!(e, RuntimeError::CapabilityDenied(ref c) if c == "ai.invoke"));
    }

    // ---- WS18-03.9 config ---------------------------------------------------

    #[test]
    fn config_get_missing_key_is_unit() {
        let bindings = SystemBindings::new().with_config(Box::new(MemConfig::default()));
        let grant = Grants::none().with(Capability::any("config.read"));
        let v = run(r#"fn main() { config::get("theme") }"#, bindings, grant).unwrap();
        assert!(matches!(v, Value::Unit));
    }

    // ---- WS18-03.10 proc/ipc ------------------------------------------------

    #[test]
    fn ipc_recv_gated_by_capability() {
        let bindings = SystemBindings::new().with_ipc(Box::new(StubIpc));
        let grant = Grants::none().with(Capability::any("ipc.recv"));
        let v = run(r#"fn main() { ipc::recv("worker") }"#, bindings, grant).unwrap();
        assert_eq!(v.display(), "msg-from:worker");
    }

    // ---- backend absence ----------------------------------------------------

    #[test]
    fn granted_but_no_backend_is_clean_error() {
        // Capability granted, but no fs backend wired → clean runtime error,
        // never treated as an enum constructor.
        let e = run(
            r#"fn main() { fs::read("/x") }"#,
            SystemBindings::new(),
            Grants::none().with(Capability::any("fs.read")),
        )
        .unwrap_err();
        assert!(matches!(e, RuntimeError::Msg(ref m) if m.contains("no fs backend")));
    }

    #[test]
    fn end_to_end_fs_then_ai_scenario() {
        // Host-side rehearsal of the WS18-03.12 VM-103 scenario: a script reads
        // a file via the FS capability and classifies it via the AI capability.
        let mut fs = MemFs::default();
        fs.files
            .insert("/etc/nexacore/msg".to_string(), "buy now cheap".to_string());
        let bindings = SystemBindings::new()
            .with_fs(Box::new(fs))
            .with_ai(Box::new(StubAi));
        let grants = Grants::none()
            .with(Capability::scoped("fs.read", "/etc/nexacore"))
            .with(Capability::any("ai.classify"));
        let src = r#"
            fn main() {
                let text = fs::read("/etc/nexacore/msg");
                ai::classify(text)
            }
        "#;
        let v = run(src, bindings, grants).unwrap();
        assert_eq!(v.display(), "spam");
    }
}
