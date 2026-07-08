//! `remote` — minimal Ollama client over the NexaCore NET syscalls (TASK-13,
//! ADR-0035 D4).
//!
//! Drives `POST /api/generate` (`stream: false`) against the LAN Ollama
//! endpoint using the M0-proven TCP chain (`NetSocket`/`NetConnect`/
//! `NetSend`/`NetRecv` + `TaskYield` polling — same ABI and patterns as
//! `nexacore-netcheck-image`).  HTTP framing is reused from `nexacore-cmd-curl`
//! (`no_std`, zero deps); JSON encode/decode is `serde_json` with
//! `alloc` only — Ollama's reply is untrusted network input, so a real
//! parser is mandatory (no hand-rolled extraction).
//!
//! Every failure is a [`RemoteError`] — the caller (the serve loop) maps
//! ANY remote failure to the LocalCpu fallback, which is exactly the M1
//! failover semantics (GPU down → CPU serves).
//!
//! # Runtime-settable endpoint (TASK-23, ADR-0045 D5)
//!
//! The connect address is no longer a compile-time constant. At boot
//! `main.rs` reads `/config/ai.cfg` from the NCFS service and calls
//! [`set_connect_addr`] if the file is present and valid; otherwise the
//! built-in default (`127.0.0.1:11434`, `0x2CAA` in BE) is kept.
//! Both [`probe_ollama_reachable`] and [`generate`] read the 6 bytes
//! from [`RUNTIME_CONNECT_ADDR`] into a local copy on every call — there
//! is no caching issue because the address is set once at boot before
//! the serve loop starts.
//!
//! Access discipline: `RUNTIME_CONNECT_ADDR` is a `static mut`.  It is
//! accessed exclusively through `core::ptr::addr_of!` / `addr_of_mut!`
//! raw-pointer reads/writes, never through a `&` / `&mut` reference.
//! The runtime is a single-threaded task; there is no concurrent access.
//!
//! # Budgets
//!
//! - Connect/send failures surface immediately (Ollama down → TCP RST).
//! - The receive loop polls with a bounded budget
//!   ([`RECV_POLL_BUDGET`]); LLM generation takes seconds (model load
//!   ~6.4 s on first call), so the budget is far larger than netcheck's
//!   `/api/tags` probe.  Budget exhaustion is a failover, not a hang.
//! - The response accumulator is a 16 KiB BSS buffer ([`ACC_CAP`]) —
//!   single non-streamed JSON object replies for short prompts fit with
//!   ample margin; overflow is a clean [`RemoteError::Oversize`].

use alloc::string::String;

use nexacore_cmd_curl::{HttpMethod, HttpRequest, build_request, parse_response};
use serde::{Deserialize, Serialize};

use crate::{syscall2, task_yield, write};

// =============================================================================
// NET syscall numbers (mirror nexacore_kernel::syscall — same as netcheck)
// =============================================================================

/// `NetSocket (103)` — allocate a socket. ABI `(domain, type) -> rax=handle`.
const SYS_NET_SOCKET: u64 = 103;
/// `NetConnect (107)` — connect a socket. ABI `(handle, addr_ptr, addr_len)`.
const SYS_NET_CONNECT: u64 = 107;
/// `NetSend (108)` — send on a socket. ABI `(handle, buf_ptr, buf_len) ->
/// rax=bytes_sent`.
const SYS_NET_SEND: u64 = 108;
/// `NetRecv (109)` — receive from a socket. ABI `(handle, buf_ptr, buf_len) ->
/// rax=bytes_copied` (0 when nothing is buffered yet — poll + yield).
const SYS_NET_RECV: u64 = 109;
/// `NetClose (112)` — close a socket. ABI `(handle)`.
const SYS_NET_CLOSE: u64 = 112;

// =============================================================================
// Probe budgets (lightweight reachability check)
// =============================================================================

/// Per-`NetRecv` chunk size for the lightweight probe.
///
/// The `/api/tags` response is small (JSON array of model metadata); 512
/// bytes is more than enough to hold the status line plus initial headers,
/// which is all we need to confirm reachability.
const PROBE_CHUNK_CAP: usize = 512;

/// Bounded receive budget for the probe: one `NetRecv` + one `TaskYield`
/// per iteration.  We only need a few bytes back (any HTTP response), so
/// the budget is kept much smaller than [`RECV_POLL_BUDGET`].  Budget
/// exhaustion is "unreachable", never a hang.
const PROBE_RECV_BUDGET: u32 = 50_000;

/// Bounded send budget for the probe request.
const PROBE_SEND_BUDGET: u32 = 10_000;

/// Static receive staging buffer for the probe — BSS, not the stack.
static mut PROBE_CHUNK: [u8; PROBE_CHUNK_CAP] = [0; PROBE_CHUNK_CAP];

// =============================================================================
// Endpoint configuration
// =============================================================================

/// Default Ollama LAN endpoint host (LXC 101) — the M0/M1 primary.
///
/// This constant is the compile-time fallback used as the HTTP `Host`
/// header value when the runtime connect address is the default.  At boot,
/// `main.rs` may overwrite the runtime address with a value read from
/// `/config/ai.cfg` via [`set_connect_addr`].
const DEFAULT_OLLAMA_HOST: &str = "127.0.0.1";

/// Runtime-settable connect address for the Ollama endpoint.
///
/// Packed `SocketApiAddr`: four IPv4 octets followed by the port in
/// network (big-endian) byte order (`11434 = 0x2CAA`).  Same wire format
/// as `nexacore-netcheck-image` (TASK-05).
///
/// Initialised to the compile-time default (`127.0.0.1:11434`).
/// `main.rs` calls [`set_connect_addr`] at boot if `/config/ai.cfg` is
/// present and decodes successfully.
///
/// # Access discipline
///
/// `SAFETY` applies at every call site: this `static mut` is NEVER
/// accessed through a `&` or `&mut` reference (that would be instant UB
/// for a `static mut` in Rust 2024). All reads copy the 6 bytes via
/// `core::ptr::addr_of!(RUNTIME_CONNECT_ADDR)` into a local `[u8; 6]`
/// before use; writes use `core::ptr::addr_of_mut!(RUNTIME_CONNECT_ADDR)`
/// and `core::ptr::write`. The runtime is a single-threaded task so there
/// is no concurrent-access concern.
#[allow(
    static_mut_refs,
    reason = "accessed only via addr_of!/addr_of_mut!, never through & or &mut"
)]
static mut RUNTIME_CONNECT_ADDR: [u8; 6] = [127, 0, 0, 1, 0x2C, 0xAA];

/// Model served by the remote backend — runtime-settable at boot via
/// the config file; starts as the default.
///
/// A 128-byte BSS buffer stores the NUL-padded model name.  Only the
/// first [`RUNTIME_MODEL_LEN`] bytes are valid UTF-8; the rest are zero.
const MODEL_BUF_CAP: usize = 128;

/// Byte count of the currently active model name in [`RUNTIME_MODEL_BUF`].
static mut RUNTIME_MODEL_LEN: usize = 13; // "gemma4:latest"

/// BSS buffer holding the currently active model name (UTF-8, no NUL
/// terminator).  Access via [`connect_model`].
#[allow(
    static_mut_refs,
    reason = "accessed only via addr_of!/addr_of_mut!, never through & or &mut"
)]
static mut RUNTIME_MODEL_BUF: [u8; MODEL_BUF_CAP] = {
    let mut buf = [0u8; MODEL_BUF_CAP];
    // "gemma4:latest" = 13 bytes
    buf[0] = b'g';
    buf[1] = b'e';
    buf[2] = b'm';
    buf[3] = b'm';
    buf[4] = b'a';
    buf[5] = b'4';
    buf[6] = b':';
    buf[7] = b'l';
    buf[8] = b'a';
    buf[9] = b't';
    buf[10] = b'e';
    buf[11] = b's';
    buf[12] = b't';
    buf
};

// =============================================================================
// Runtime endpoint accessors (TASK-23, ADR-0045 D5)
// =============================================================================

/// Read the current runtime connect address as a 6-byte copy.
///
/// Returns `[ip0, ip1, ip2, ip3, port_hi, port_lo]` (port big-endian).
/// Copies the bytes out of the `static mut` via a raw pointer read so
/// that no `&` reference to the `static mut` is ever formed.
///
/// # Example
///
/// ```ignore
/// // (bare-metal only)
/// let addr = remote::connect_addr();
/// // addr[4..] are the port bytes in big-endian order
/// ```
pub fn connect_addr() -> [u8; 6] {
    // SAFETY: single-threaded task; no concurrent write can occur;
    // `addr_of!` does not form a reference, it only takes the address.
    // `ptr::read` copies 6 bytes from the static storage into a local.
    unsafe { core::ptr::read(core::ptr::addr_of!(RUNTIME_CONNECT_ADDR)) }
}

/// Overwrite the runtime connect address with `addr`.
///
/// `addr` must be `[ip0, ip1, ip2, ip3, port_hi, port_lo]`.
/// Called once at boot by `main.rs` when `/config/ai.cfg` decodes
/// successfully; never called again (read-at-boot semantics, ADR-0045 D5).
///
/// # Example
///
/// ```ignore
/// // (bare-metal only)
/// remote::set_connect_addr([10, 0, 0, 2, 0x2C, 0xAA]);
/// ```
pub fn set_connect_addr(addr: [u8; 6]) {
    // SAFETY: single-threaded task; no concurrent read can observe a
    // torn write; `addr_of_mut!` does not form a `&mut` reference.
    // `ptr::write` performs one atomic-width store of the 6 bytes.
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(RUNTIME_CONNECT_ADDR), addr) };
}

/// Set the active model name from a UTF-8 string slice.
///
/// Silently truncates to [`MODEL_BUF_CAP`] bytes on overflow (the caller
/// validates length before calling — `AiEndpointConfig::validate()` caps
/// model at `CONFIG_MAX_STR = 128` bytes which matches [`MODEL_BUF_CAP`]).
/// Called once at boot by `main.rs`; same read-at-boot discipline.
///
/// # Example
///
/// ```ignore
/// // (bare-metal only)
/// remote::set_model("llama3:8b");
/// ```
pub fn set_model(model: &str) {
    let bytes = model.as_bytes();
    let len = bytes.len().min(MODEL_BUF_CAP);
    // SAFETY: single-threaded; `addr_of_mut!` does not form a reference.
    unsafe {
        let dst = core::ptr::addr_of_mut!(RUNTIME_MODEL_BUF).cast::<u8>();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len);
        core::ptr::write(core::ptr::addr_of_mut!(RUNTIME_MODEL_LEN), len);
    }
}

/// Copy the current model name into `buf` and return the byte count.
///
/// Returns 0 if the name is empty or the buffer is too small.
fn copy_model_into(buf: &mut [u8]) -> usize {
    // SAFETY: single-threaded; raw pointer reads avoid & on static mut.
    let len = unsafe { core::ptr::read(core::ptr::addr_of!(RUNTIME_MODEL_LEN)) };
    if len == 0 || buf.len() < len {
        return 0;
    }
    // SAFETY: RUNTIME_MODEL_BUF[..len] is valid UTF-8; len <= MODEL_BUF_CAP.
    unsafe {
        let src = core::ptr::addr_of!(RUNTIME_MODEL_BUF).cast::<u8>();
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
    }
    len
}

/// Generation budget forwarded to Ollama (`options.num_predict`).
/// Small on purpose: the M1 smoke asks a short question and the reply
/// must fit the 4096-byte AI payload bound with margin.
const REMOTE_NUM_PREDICT: u32 = 64;

/// `SocketDomain::Inet` discriminant for the `NetSocket` ABI.
const DOMAIN_INET: u64 = 0;
/// `SocketType::Stream` discriminant for the `NetSocket` ABI.
const TYPE_STREAM: u64 = 0;

// =============================================================================
// Buffers + budgets
// =============================================================================

/// Response accumulator capacity (BSS).  A non-streamed `/api/generate`
/// reply carries the generated text plus the `context` token array —
/// a few KiB for short prompts; 16 KiB is ample.
const ACC_CAP: usize = 16 * 1024;

/// Per-`NetRecv` chunk size — well under the NET relay payload bound.
const CHUNK_CAP: usize = 512;

/// Bounded receive budget: one `NetRecv` + one `TaskYield` per
/// iteration.  Generation is slow (seconds, incl. first-call model
/// load); 5 M cooperative rotations bound the wait while guaranteeing
/// termination → failover.
const RECV_POLL_BUDGET: u32 = 5_000_000;

/// Receive accumulator — BSS, not the 4 KiB user stack.
static mut ACC: [u8; ACC_CAP] = [0; ACC_CAP];

/// `NetRecv` staging chunk — BSS for the same reason.
static mut CHUNK: [u8; CHUNK_CAP] = [0; CHUNK_CAP];

// =============================================================================
// Errors
// =============================================================================

/// Why the remote backend could not serve — every variant routes the
/// caller to the LocalCpu fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteError {
    /// `NetSocket` failed (no socket slot / service unavailable).
    Socket,
    /// `NetConnect` failed (Ollama down → RST, or no route).
    Connect,
    /// `NetSend` failed or sent short.
    Send,
    /// `NetRecv` returned a fatal errno.
    Recv,
    /// Receive budget exhausted before a complete response arrived.
    Timeout,
    /// The response outgrew the accumulator.
    Oversize,
    /// Malformed HTTP (no header terminator / bad status line).
    Http,
    /// HTTP status was not 200.
    Status,
    /// The body was not the expected JSON shape.
    Json,
    /// The model is not resident (cold / mid-(un)load): Ollama replied 200
    /// with an empty `response` and `done_reason != "stop"`. Not a real
    /// answer — the caller retries (model is loading) or falls back to
    /// LocalCpu (ADR-0050).
    NotReady,
}

impl RemoteError {
    /// Short static tag for serial audit lines.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Connect => "connect",
            Self::Send => "send",
            Self::Recv => "recv",
            Self::Timeout => "timeout",
            Self::Oversize => "oversize",
            Self::Http => "http",
            Self::Status => "status",
            Self::Json => "json",
            Self::NotReady => "notready",
        }
    }
}

// =============================================================================
// Ollama JSON shapes (mirror nexacore-runtime/src/provider/ollama.rs)
// =============================================================================

/// `POST /api/generate` request body (non-streaming).
#[derive(Serialize)]
struct GenerateBody<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
    options: GenOptions,
}

/// Generation options subset.
#[derive(Serialize)]
struct GenOptions {
    num_predict: u32,
}

/// `/api/generate` non-streamed reply — only the fields we consume;
/// `#[serde(default)]` tolerates Ollama omitting them.
#[derive(Deserialize, Default)]
struct GenerateChunk {
    #[serde(default)]
    response: String,
    #[serde(default)]
    eval_count: u32,
    /// Why generation stopped. A resident model that produced an answer
    /// reports `"stop"` (or `"length"`); a model that was NOT resident
    /// (cold / mid-(un)load) replies with an empty `response` and a
    /// `done_reason` of `"load"`/`"unload"` — that is NOT a real answer
    /// (ADR-0050).
    #[serde(default)]
    done_reason: String,
}

// =============================================================================
// Public entry
// =============================================================================

/// Probe whether the Ollama endpoint is reachable with a minimal HTTP request.
///
/// Opens a TCP socket, connects to `OLLAMA_HOST:OLLAMA_PORT`, sends a tiny
/// `GET /api/tags HTTP/1.0\r\n\r\n` request, and attempts to read back any
/// bytes.  Returns `true` if at least one byte is received before the budget
/// is exhausted, `false` on any failure (socket, connect, send, recv timeout).
///
/// # Non-blocking guarantee
///
/// Every wait is bounded: the send loop runs at most [`PROBE_SEND_BUDGET`]
/// iterations and the receive loop at most [`PROBE_RECV_BUDGET`] iterations.
/// Each iteration issues one `TaskYield`, so the cooperative scheduler sees
/// regular yields.  Budget exhaustion → `false`; it never hangs.
///
/// # Reuse of the NET chain
///
/// This function reuses exactly the same `NetSocket` / `NetConnect` /
/// `NetSend` / `NetRecv` / `NetClose` syscall chain used by [`generate`],
/// with the same ABI and clobber set.  The only difference is the HTTP
/// payload (a minimal GET instead of a POST) and the much smaller budgets.
///
/// # Example (doctest skipped under `no_std`)
///
/// ```ignore
/// // In integration context with the NET syscalls available:
/// let up = remote::probe_ollama_reachable();
/// assert!(up || !up); // always returns without hanging
/// ```
pub fn probe_ollama_reachable() -> bool {
    // Copy the runtime endpoint into a local — no & on static mut.
    let addr = connect_addr();

    // ── Allocate socket. ──
    // SAFETY: no pointer arguments.
    let (handle, errno) = unsafe { syscall2(SYS_NET_SOCKET, DOMAIN_INET, TYPE_STREAM, 0, 0, 0, 0) };
    if errno != 0 {
        return false;
    }

    // ── Connect to the runtime Ollama endpoint. ──
    // SAFETY: `addr` is a stack-local copy of the 6-byte connect address,
    // valid for the duration of this syscall call.
    let (_, errno) = unsafe {
        syscall2(
            SYS_NET_CONNECT,
            handle,
            addr.as_ptr() as u64,
            addr.len() as u64,
            0,
            0,
            0,
        )
    };
    if errno != 0 {
        probe_close(handle);
        return false;
    }

    // Minimal HTTP/1.0 GET — no keep-alive, no headers needed beyond Host.
    // HTTP/1.0 means the server closes the connection after the response,
    // making it easy to detect completion (connection close) in the recv loop.
    // The Host header is built at compile time using the default; for the
    // probe we only need any response back (the status line suffices), so
    // the Host value does not affect routing in typical LAN setups.
    const PROBE_REQ: &[u8] = b"GET /api/tags HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";

    // ── Send the probe request. ──
    if probe_send_all(handle, PROBE_REQ).is_err() {
        probe_close(handle);
        return false;
    }

    // ── Receive: any bytes back = reachable. ──
    let reachable = probe_recv_any(handle);
    probe_close(handle);
    reachable
}

/// Send all bytes in `buf` on `handle`, yielding on would-block with a
/// bounded budget.  Used exclusively by [`probe_ollama_reachable`] to
/// keep the probe path independent of `send_all`'s BSS accumulators.
fn probe_send_all(handle: u64, buf: &[u8]) -> Result<(), ()> {
    let mut offset: usize = 0;
    let mut budget = PROBE_SEND_BUDGET;
    while offset < buf.len() {
        // SAFETY: `buf` is alive for the duration of the call; offset is
        // bounded by `buf.len()`.
        let (sent, errno) = unsafe {
            syscall2(
                SYS_NET_SEND,
                handle,
                buf.as_ptr().wrapping_add(offset) as u64,
                (buf.len() - offset) as u64,
                0,
                0,
                0,
            )
        };
        if errno != 0 {
            return Err(());
        }
        let sent = sent as usize;
        if sent == 0 {
            budget = budget.checked_sub(1).ok_or(())?;
            task_yield();
            continue;
        }
        offset += sent;
    }
    Ok(())
}

/// Poll `NetRecv` until any bytes arrive on `handle`, yielding between
/// attempts.  Returns `true` on the first non-zero read; `false` on
/// fatal errno or budget exhaustion.  Used exclusively by
/// [`probe_ollama_reachable`] to keep the probe separate from
/// `recv_response`'s BSS accumulator.
fn probe_recv_any(handle: u64) -> bool {
    for _ in 0..PROBE_RECV_BUDGET {
        // SAFETY: PROBE_CHUNK is a static BSS buffer accessed only on
        // this probe path (single-threaded task; no concurrent access).
        let (n, errno) = unsafe {
            syscall2(
                SYS_NET_RECV,
                handle,
                core::ptr::addr_of_mut!(PROBE_CHUNK) as u64,
                PROBE_CHUNK_CAP as u64,
                0,
                0,
                0,
            )
        };
        if errno != 0 {
            // A non-zero errno after a successful connect means the remote
            // closed the connection or sent a RST — but if errno is 0 on
            // connect we interpret any errno here conservatively: we cannot
            // distinguish "RST with no data" from "server sent data then
            // closed".  Return false to be conservative (the next probe
            // will confirm either way).
            return false;
        }
        if n > 0 {
            // Any bytes received — Ollama is up.
            return true;
        }
        // Nothing yet — yield and retry within budget.
        task_yield();
    }
    // Budget exhausted without receiving any bytes.
    false
}

/// Close `handle`, best-effort.  Used exclusively by
/// [`probe_ollama_reachable`] to match the probe's open.
fn probe_close(handle: u64) {
    // SAFETY: no pointer arguments; errors are irrelevant on every call site.
    let _ = unsafe { syscall2(SYS_NET_CLOSE, handle, 0, 0, 0, 0, 0) };
}

/// Max attempts for a generate when the model reports not-ready (loading).
/// A cold model load takes a few seconds; we re-issue the request a bounded
/// number of times (yielding between attempts) before giving up to LocalCpu.
const REMOTE_GENERATE_ATTEMPTS: u32 = 6;

/// Cooperative yields between not-ready retries — gives Ollama time to finish
/// loading the model before we re-issue the request. Bounded so a permanently
/// not-ready backend still terminates → LocalCpu fallback.
const REMOTE_RETRY_YIELDS: u32 = 200_000;

/// Ask the remote Ollama backend to generate a completion for `prompt`.
///
/// Returns the generated text and the model's `eval_count` on success;
/// any failure (transport, HTTP, JSON) is a [`RemoteError`] and the
/// caller falls back to the LocalCpu engine (M1 failover semantics).
///
/// A model that is **not resident** (cold / mid-(un)load) answers an
/// `/api/generate` with an empty `response` and a `done_reason` other than
/// `"stop"` (e.g. `"load"`/`"unload"`). That is NOT a real answer: this
/// wrapper retries a bounded number of times (yielding between attempts so
/// the model finishes loading) and, if still not ready, returns
/// [`RemoteError::NotReady`] so the caller falls back — it never surfaces a
/// "successful empty answer". See ADR-0050.
pub fn generate(prompt: &str) -> Result<(String, u32), RemoteError> {
    let mut attempt: u32 = 0;
    loop {
        match generate_once(prompt) {
            Err(RemoteError::NotReady) => {
                attempt += 1;
                if attempt >= REMOTE_GENERATE_ATTEMPTS {
                    write("[ai-svc] remote: model not ready after retries -> fallback\n");
                    return Err(RemoteError::NotReady);
                }
                write("[ai-svc] remote: model loading, retrying...\n");
                for _ in 0..REMOTE_RETRY_YIELDS {
                    task_yield();
                }
            }
            other => return other,
        }
    }
}

/// Issue a single `/api/generate` round-trip (one socket lifecycle).
///
/// The endpoint address and model name are read from the runtime-settable
/// statics ([`RUNTIME_CONNECT_ADDR`], [`RUNTIME_MODEL_BUF`]) at the start
/// of every call, so the Settings-app-configured values take effect
/// immediately after boot (ADR-0045 D5).
fn generate_once(prompt: &str) -> Result<(String, u32), RemoteError> {
    // ── Read the runtime endpoint + model into stack-local copies. ──
    let addr = connect_addr();

    // Port is encoded in addr[4..5] (big-endian).
    let port = u16::from_be_bytes([addr[4], addr[5]]);

    // Reconstruct the dotted-quad host string for the HTTP Host header.
    // The host string is only used by the HTTP/1.1 Host header, not for
    // routing (the actual connection uses the raw `addr` bytes).
    let mut host_buf = [0u8; 16]; // enough for "255.255.255.255"
    let host_len = fmt_ipv4_into(&mut host_buf, [addr[0], addr[1], addr[2], addr[3]]);
    let host_str = core::str::from_utf8(&host_buf[..host_len]).unwrap_or(DEFAULT_OLLAMA_HOST);

    // Model name.
    let mut model_buf = [0u8; MODEL_BUF_CAP];
    let model_len = copy_model_into(&mut model_buf);
    // If the model buffer is uninitialised (len 0), fall back to the
    // compile-time constant so the request is always well-formed.
    let model_str = if model_len > 0 {
        core::str::from_utf8(&model_buf[..model_len]).unwrap_or("gemma4:latest")
    } else {
        "gemma4:latest"
    };

    // ── Build the HTTP request (reuse nexacore-cmd-curl, ADR-0035 D4). ──
    let body = serde_json::to_vec(&GenerateBody {
        model: model_str,
        prompt,
        stream: false,
        options: GenOptions {
            num_predict: REMOTE_NUM_PREDICT,
        },
    })
    .map_err(|_| RemoteError::Json)?;

    let request = build_request(&HttpRequest {
        method: HttpMethod::Post,
        host: String::from(host_str),
        port,
        path: String::from("/api/generate"),
        headers: alloc::vec![
            (
                String::from("Content-Type"),
                String::from("application/json")
            ),
            (String::from("Accept"), String::from("application/json")),
        ],
        body: Some(body),
    });

    // ── Socket + connect (Ollama down fails fast here with RST). ──
    // SAFETY: no pointer arguments.
    let (handle, errno) = unsafe { syscall2(SYS_NET_SOCKET, DOMAIN_INET, TYPE_STREAM, 0, 0, 0, 0) };
    if errno != 0 {
        return Err(RemoteError::Socket);
    }

    // SAFETY: `addr` is a stack-local 6-byte copy of the runtime connect
    // address; it is valid for the entire duration of this syscall.
    let (_, errno) = unsafe {
        syscall2(
            SYS_NET_CONNECT,
            handle,
            addr.as_ptr() as u64,
            addr.len() as u64,
            0,
            0,
            0,
        )
    };
    if errno != 0 {
        close(handle);
        return Err(RemoteError::Connect);
    }

    // ── Send the request (poll-send: the cooperative stack may accept
    //    0 bytes transiently while TX is busy — same would-block
    //    semantics as NetRecv, so retry with a yield and a budget). ──
    if send_all(handle, &request).is_err() {
        close(handle);
        return Err(RemoteError::Send);
    }

    // ── Poll-receive until the response is complete (or budget). ──
    let outcome = recv_response(handle);
    close(handle);
    let acc_len = outcome?;

    // ── Parse HTTP + JSON. ──
    // SAFETY: single-threaded task; ACC written only by recv_response.
    let raw = unsafe { &(*core::ptr::addr_of!(ACC))[..acc_len] };
    let resp = parse_response(raw).ok_or(RemoteError::Http)?;
    if resp.status_code != 200 {
        return Err(RemoteError::Status);
    }

    let chunk: GenerateChunk = serde_json::from_slice(&resp.body).map_err(|_| RemoteError::Json)?;

    // A non-resident / loading model replies 200 with an empty `response` and
    // a `done_reason` other than "stop" (e.g. "load"/"unload"). That is not a
    // real answer — surface it as `NotReady` so `generate` retries (the model
    // is loading) or the caller falls back, instead of returning a
    // "successful empty answer" (the M1 empty-output bug; ADR-0050).
    if chunk.response.is_empty() && chunk.done_reason != "stop" {
        return Err(RemoteError::NotReady);
    }

    Ok((chunk.response, chunk.eval_count))
}

// =============================================================================
// Internals
// =============================================================================

/// Bounded send budget: one `NetSend` + one `TaskYield` per zero-byte
/// iteration while the TX path is busy.
const SEND_POLL_BUDGET: u32 = 100_000;

/// Send ALL of `buf` on `handle`, yielding between attempts when the
/// stack transiently accepts 0 bytes (cooperative would-block), and
/// advancing on partial writes.  Errors on a fatal errno or when the
/// budget is exhausted.
fn send_all(handle: u64, buf: &[u8]) -> Result<(), ()> {
    let mut offset: usize = 0;
    let mut budget = SEND_POLL_BUDGET;
    while offset < buf.len() {
        // SAFETY: `buf` is alive for the duration of the call; the
        // offset is bounded by the loop condition.
        let (sent, errno) = unsafe {
            syscall2(
                SYS_NET_SEND,
                handle,
                buf.as_ptr().wrapping_add(offset) as u64,
                (buf.len() - offset) as u64,
                0,
                0,
                0,
            )
        };
        if errno != 0 {
            return Err(());
        }
        let sent = sent as usize;
        if sent == 0 {
            budget = budget.checked_sub(1).ok_or(())?;
            task_yield();
            continue;
        }
        offset += sent;
    }
    Ok(())
}

/// Close `handle`, best-effort (errors are irrelevant on every path that
/// calls this).
fn close(handle: u64) {
    // SAFETY: no pointer arguments.
    let _ = unsafe { syscall2(SYS_NET_CLOSE, handle, 0, 0, 0, 0, 0) };
}

/// Poll `NetRecv` into [`ACC`] until the HTTP response is complete:
/// headers terminated AND (`Content-Length` satisfied when present).
/// Returns the accumulated length.
fn recv_response(handle: u64) -> Result<usize, RemoteError> {
    let mut acc_len: usize = 0;

    for _ in 0..RECV_POLL_BUDGET {
        // SAFETY: CHUNK is a static BSS buffer accessed only here
        // (single-threaded task).
        let (n, errno) = unsafe {
            syscall2(
                SYS_NET_RECV,
                handle,
                core::ptr::addr_of_mut!(CHUNK) as u64,
                CHUNK_CAP as u64,
                0,
                0,
                0,
            )
        };
        if errno != 0 {
            // Fatal errno: if we already hold a complete-looking response
            // the parser will decide; otherwise it is a transport error.
            // (Remote close after `Connection: close` may surface as an
            // errno once the buffered bytes are drained.)
            if acc_len > 0 && response_complete(acc_len) {
                return Ok(acc_len);
            }
            write("[ai-svc] remote: recv errno=");
            write_hex_u8(errno as u8);
            write(" acc_len=");
            write_hex_u8((acc_len & 0xFF) as u8);
            write("\n");
            return Err(RemoteError::Recv);
        }

        let n = n as usize;
        if n == 0 {
            // Nothing buffered yet — let the service/driver run.
            if acc_len > 0 && response_complete(acc_len) {
                return Ok(acc_len);
            }
            task_yield();
            continue;
        }

        if acc_len + n > ACC_CAP {
            return Err(RemoteError::Oversize);
        }
        // SAFETY: single-threaded task; bounds checked above.
        unsafe {
            let acc = core::ptr::addr_of_mut!(ACC).cast::<u8>();
            let chunk = core::ptr::addr_of!(CHUNK).cast::<u8>();
            core::ptr::copy_nonoverlapping(chunk, acc.add(acc_len), n);
        }
        acc_len += n;

        if response_complete(acc_len) {
            return Ok(acc_len);
        }
    }

    write("[ai-svc] remote: recv budget exhausted\n");
    Err(RemoteError::Timeout)
}

/// Whether [`ACC`]`[..acc_len]` holds a complete HTTP response:
/// header terminator present and, when a `Content-Length` header is
/// readable, the body has reached it.  Without a `Content-Length` we
/// require only the terminator plus a non-empty body and let the JSON
/// parse decide (the remote uses `Connection: close`, so trailing bytes
/// drain before the close errno).
fn response_complete(acc_len: usize) -> bool {
    // SAFETY: single-threaded task; read-only view of ACC.
    let raw = unsafe { &(*core::ptr::addr_of!(ACC))[..acc_len] };
    let Some(sep) = find_double_crlf(raw) else {
        return false;
    };
    let body_len = acc_len - (sep + 4);

    if let Some(cl) = content_length(raw.get(..sep).unwrap_or(&[])) {
        return body_len >= cl;
    }
    body_len > 0
}

/// Write a byte as two hex digits (diagnostic lines).
fn write_hex_u8(v: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let buf = [HEX[(v >> 4) as usize], HEX[(v & 0xF) as usize]];
    if let Ok(s) = core::str::from_utf8(&buf) {
        write(s);
    }
}

/// Locate the `\r\n\r\n` header terminator.
fn find_double_crlf(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Format `octets` as a dotted-quad IPv4 string into `buf`.
///
/// Returns the number of bytes written.  `buf` must be at least 15 bytes
/// (`"255.255.255.255"` is 15 chars).  The result is always valid ASCII
/// and can be used with `core::str::from_utf8`.
fn fmt_ipv4_into(buf: &mut [u8; 16], octets: [u8; 4]) -> usize {
    // Write each decimal octet separated by '.' into buf without allocation.
    let mut pos = 0usize;
    for (i, &oct) in octets.iter().enumerate() {
        // Write up to 3 decimal digits for this octet.
        if oct >= 100 {
            if pos < buf.len() {
                buf[pos] = b'0' + oct / 100;
            }
            pos += 1;
        }
        if oct >= 10 {
            if pos < buf.len() {
                buf[pos] = b'0' + (oct / 10) % 10;
            }
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b'0' + oct % 10;
        }
        pos += 1;
        // Append '.' after every octet except the last.
        if i < 3 {
            if pos < buf.len() {
                buf[pos] = b'.';
            }
            pos += 1;
        }
    }
    pos.min(buf.len())
}

/// Extract a `Content-Length` value from the raw header block
/// (case-insensitive name match, ASCII digits only).
fn content_length(headers: &[u8]) -> Option<usize> {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, rest) = line.split_at(colon);
        if !name.eq_ignore_ascii_case(b"content-length") {
            continue;
        }
        let value = rest.get(1..).unwrap_or(&[]);
        let trimmed: &[u8] = {
            let start = value.iter().position(|b| !b.is_ascii_whitespace())?;
            let end = value.iter().rposition(|b| !b.is_ascii_whitespace())?;
            value.get(start..=end).unwrap_or(&[])
        };
        let mut n: usize = 0;
        for &b in trimmed {
            if !b.is_ascii_digit() {
                return None;
            }
            n = n.checked_mul(10)?.checked_add((b - b'0') as usize)?;
        }
        return Some(n);
    }
    None
}
